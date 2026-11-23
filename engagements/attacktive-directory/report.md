# Penetration Test Report — Attacktive Directory

| | |
|---|---|
| **Target** | `ATTACKTIVEDIREC` (Domain Controller) / `10.129.173.201` |
| **Domain** | `spookysec.local` (NetBIOS: `THM-AD`) |
| **Platform** | TryHackMe — https://tryhackme.com/room/attacktivedirectory |
| **Assessment type** | Black-box Active Directory penetration test |
| **Date** | 2026-11-23 |
| **Result** | **Full domain compromise — Domain Admin achieved** |
| **Overall risk** | 🔴 **Critical** |

---

## 1. Executive summary

The target is a Windows Server 2019 **Active Directory Domain Controller** for the `spookysec.local` domain. Starting from a completely unauthenticated position, testing achieved **full domain compromise (Domain Administrator)**.

The attack required no software exploit — it was a chain of **identity and configuration weaknesses**. A service account (`svc-admin`) was configured without Kerberos pre-authentication, allowing its password hash to be retrieved anonymously and cracked offline (**AS-REP Roasting**). Those credentials exposed an SMB share containing a second account's password stored with trivially reversible **base64 encoding**. That second account (`backup`) held **directory replication rights**, which were abused to replicate the entire domain password database (**DCSync**), yielding the Administrator password hash. That hash was used directly — without cracking — to authenticate to the Domain Controller (**Pass-the-Hash**), granting Domain Admin.

This mirrors how real Active Directory environments fall: not through a single CVE, but through weak service-account configuration, poor secret storage, and over-privileged accounts, chained together.

**Key outcomes**
- Anonymous **AS-REP Roast** → `svc-admin` credential (`management2005`).
- **Base64-stored** credential looted from an SMB share → `backup` account.
- **DCSync** via `backup`'s replication rights → all domain NTLM hashes (incl. Administrator and `krbtgt`).
- **Pass-the-Hash** → interactive Domain Admin shell on the DC.

---

## 2. Finding register

| ID | Finding | Severity | CVSS |
|----|---------|----------|------|
| F-01 | Kerberos pre-authentication disabled on `svc-admin` (AS-REP Roastable) | **High** | 8.1 |
| F-02 | Weak, crackable account password | **High** | 7.5 |
| F-03 | Credentials stored with reversible base64 encoding on a readable SMB share | **High** | 7.5 |
| F-04 | Over-privileged `backup` account with directory replication rights (DCSync) | **Critical** | 9.1 |
| F-05 | Anonymous SMB null sessions permitted | **Medium** | 5.3 |
| F-06 | Password reuse between `Administrator` and a secondary admin account (`a-spooks`) | **Medium** | 5.0 |

---

## 3. Findings (detail)

### F-01 — Kerberos pre-authentication disabled (AS-REP Roasting)

- **Severity:** High (CVSS 8.1)
- **Description:** The `svc-admin` account has "Do not require Kerberos pre-authentication" set. The DC will issue an AS-REP — partly encrypted with the account's password key — to any unauthenticated requester, enabling offline cracking.
- **Evidence:**
  ```
  impacket-GetNPUsers spookysec.local/svc-admin -no-pass -dc-ip 10.129.173.201
  -> $krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:...
  john asrep.hash --wordlist=passwordlist.txt  -> management2005
  ```
- **Impact:** Anonymous recovery of a valid domain credential.
- **Remediation:** Enable Kerberos pre-authentication on all accounts (remove `DONT_REQ_PREAUTH`). Audit with `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`.

### F-02 — Weak account password

- **Severity:** High (CVSS 7.5)
- **Description:** `svc-admin`'s password (`management2005`) was present in a standard wordlist and cracked in under a second.
- **Impact:** Negates the protection of Kerberos hashing.
- **Remediation:** Enforce long, random passwords for service accounts (ideally Group Managed Service Accounts / gMSA with 120-char auto-rotated passwords). Enforce a strong policy + breached-password screening for users.

### F-03 — Credentials stored with reversible encoding on a readable share

- **Severity:** High (CVSS 7.5)
- **Description:** A readable `backup` SMB share contained `backup_credentials.txt`, holding `backup@spookysec.local:backup2517860` as **base64** — encoding, not encryption, reversible instantly with no key.
- **Evidence:**
  ```
  smbclient //10.129.173.201/backup -U svc-admin -> get backup_credentials.txt
  echo 'YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw' | base64 -d
  -> backup@spookysec.local:backup2517860
  ```
- **Impact:** Direct disclosure of a privileged account's credential.
- **Remediation:** Never store credentials in file shares. Restrict share permissions to least privilege; use a secrets manager; audit shares for secrets.

### F-04 — Over-privileged account with replication rights (DCSync)

- **Severity:** Critical (CVSS 9.1)
- **Description:** The `backup` account holds `DS-Replication-Get-Changes` / `-All`, letting it impersonate a DC and replicate all account secrets (DCSync), including the Administrator and `krbtgt` hashes.
- **Evidence:**
  ```
  impacket-secretsdump spookysec.local/backup:backup2517860@10.129.173.201
  -> Administrator:500:...:0e0363213e37b94221497260b0bcb4fc:::
  -> krbtgt:502:...:0e2eb8158c27bed09861033026be4c21:::
  ```
- **Impact:** Full domain compromise; `krbtgt` disclosure enables persistent Golden Ticket forgery.
- **Remediation:** Remove replication rights from non-DC accounts; grant least privilege; monitor for DCSync (Event 4662 with replication GUIDs). Rotate `krbtgt` **twice** after exposure.

### F-05 — Anonymous SMB null sessions permitted

- **Severity:** Medium (CVSS 5.3)
- **Description:** The server accepts SMB sessions with a blank username/password, aiding anonymous enumeration.
- **Evidence:** `enum4linux -A` → `Server allows sessions using username '', password ''`.
- **Remediation:** Restrict anonymous access (`RestrictAnonymous` / `RestrictNullSessAccess`); limit anonymous enumeration of accounts and shares.

### F-06 — Administrator / secondary-admin password reuse

- **Severity:** Medium (CVSS 5.0)
- **Description:** `Administrator` and `a-spooks` (a second Domain Admin) share the same NTLM hash — identical passwords. One compromise = two.
- **Remediation:** Unique passwords per privileged account; adopt tiered admin + PAW; monitor for credential reuse.

---

## 4. Attack narrative

From an unauthenticated position, recon identified a Domain Controller (`spookysec.local`). `kerbrute` enumerated valid users via Kerberos pre-auth responses. `svc-admin` lacked pre-authentication, so its AS-REP was retrieved and cracked offline (`management2005`) — **AS-REP Roasting**. Those creds exposed a readable `backup` SMB share whose `backup_credentials.txt` held a **base64-encoded** password for the `backup` account. `backup` had **directory replication rights**, abused via **DCSync** (`secretsdump`) to dump every domain hash, including Administrator. The Administrator **NTLM hash** was used in a **Pass-the-Hash** authentication to the DC over WinRM (Evil-WinRM), yielding an interactive **Domain Admin** session.

---

## 5. Remediation roadmap

| Priority | Action | Addresses |
|----------|--------|-----------|
| **Immediate** | Remove replication rights from `backup`; rotate `krbtgt` twice | F-04 |
| **Immediate** | Enable Kerberos pre-auth on all accounts | F-01 |
| **Short-term** | Remove the credential file; lock down shares; rotate exposed creds | F-03 |
| **Short-term** | Strong/gMSA passwords; unique passwords per admin | F-02, F-06 |
| **Hardening** | Disable null sessions; enable DCSync/Event-4662 monitoring | F-05, F-04 |

---

## 6. Appendix — proof

- User flag: `TryHackMe{K3rb3r0s_Pr3_4uth}`
- PrivEsc flag: `TryHackMe{B4ckM3UpSc0tty!}`
- Root flag: `TryHackMe{4ctiveD1rectoryM4st3r}`
- Final access: `thm-ad\administrator` (Domain Admin)
- Full technical narrative: [`walkthrough.md`](./walkthrough.md) · Command log: [`commands.md`](./commands.md)
- **Scope & authorization:** single authorized TryHackMe target, isolated VPN.
