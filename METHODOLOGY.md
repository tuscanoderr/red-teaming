# Assessment Methodology

The repeatable process applied to every engagement in this repository. It is aligned to the **Penetration Testing Execution Standard (PTES)** and, for web application targets, the **OWASP Web Security Testing Guide (WSTG)**. The intent is that any reader can follow the same phases and arrive at the same result — the hallmark of a disciplined assessment versus ad-hoc hacking.

---

## Phase 0 — Engagement setup & scope

Before any packet is sent:

- **Authorization confirmed.** Target is in-scope (a TryHackMe room assigned to my account). Nothing outside the single target IP is touched.
- **Rules of engagement.** Single host, isolated VPN, no destructive actions beyond what proves the finding.
- **Working directory prepared.** One folder per engagement; evidence captured as I go, not reconstructed afterward.

```bash
# Connect to the isolated lab network, then confirm reachability
ping -c 3 <TARGET_IP>
export IP=<TARGET_IP>        # referenced throughout as $IP
```

---

## Phase 1 — Reconnaissance & enumeration

> *"Enumeration is the heartbeat of a pentest." The majority of engagement time lives here. A missed service is a missed finding.*

### 1.1 Host discovery & port scan

```bash
# Fast full-port sweep to find everything listening
nmap -p- --min-rate 10000 -T4 $IP -oN scans/01-allports.txt

# Deep scan (service versions + default scripts) on the discovered ports
nmap -p <PORTS> -sC -sV -oN scans/02-services.txt $IP
```

Record, for every open port: service, version, and the first hypothesis about how it could be abused.

### 1.2 Service-specific enumeration

Drill into each service with the right tool:

| Service | Tooling / technique |
|---------|---------------------|
| HTTP/HTTPS | `whatweb`, `gobuster`/`feroxbuster` dir & vhost brute, `nikto`, manual source review, tech fingerprint (CMS → version → known CVEs) |
| SMB (139/445) | `enum4linux-ng`, `smbclient -L`, `smbmap`, null-session checks |
| FTP (21) | anonymous login, `ftp` banner, writable dirs |
| SSH (22) | version → known CVEs, auth methods, user enumeration |
| DNS (53) | zone transfer `dig axfr`, subdomain brute |
| LDAP/Kerberos (389/88) | AD enumeration — users, SPNs, AS-REP-roastable accounts |
| RPC/NFS | `rpcclient`, `showmount -e` |

### 1.3 Attack-surface synthesis

Consolidate findings into a short list of *credible* attack paths ranked by likelihood and impact. This is the decision point that separates a methodical tester from a tool-runner.

---

## Phase 2 — Vulnerability analysis

- Map versions/configurations to known vulnerabilities (CVE, exploit-db, vendor advisories).
- **Validate before trusting.** Scanner output is a lead, not a finding. Confirm the vulnerable code path actually exists on this target.
- Assign a provisional severity using **CVSS v3.1** so prioritization is defensible.

---

## Phase 3 — Exploitation (gaining a foothold)

- Choose the lowest-noise, highest-reliability path first.
- Prefer understanding the exploit over blindly firing it — document *why* it works.
- Capture evidence at the moment of compromise (command + output + timestamp).

```bash
# Example: catch a reverse shell
nc -lvnp 4444
# Stabilize the shell
python3 -c 'import pty; pty.spawn("/bin/bash")'   # then Ctrl-Z, stty raw -echo, fg
```

Record the **initial access vector** clearly — this is the primary finding.

---

## Phase 4 — Post-exploitation & privilege escalation

### 4.1 Situational awareness

```bash
id; whoami; hostname; uname -a          # who am I, where am I
sudo -l                                 # delegated rights
# Automated triage
./linpeas.sh    |  tee loot/linpeas.txt   # Linux
# winPEAS.exe   >  loot/winpeas.txt        # Windows
```

### 4.2 Escalation

Common vectors to check deliberately: misconfigured `sudo`, SUID/SGID binaries (GTFOBins), writable cron/service paths, kernel exploits (last resort), stored credentials, overly-permissioned tokens/groups.

### 4.3 Lateral movement (multi-host engagements)

Pivoting, credential reuse, and tunneling where the engagement has more than one host.

---

## Phase 5 — Evidence & proof of compromise

- Capture flags/objectives with the proof command visible (`cat flag`, `whoami`).
- Timestamped screenshots stored under the engagement's `assets/`.
- Extracted artifacts (hashes, config snippets) under `loot/` — sanitized where appropriate.

---

## Phase 6 — Reporting

Produce two documents per engagement:

1. **`report.md`** — the formal deliverable: executive summary, finding register (each with severity, evidence, impact, remediation), and an overall risk picture. This is what a client reads.
2. **`walkthrough.md`** — the technical narrative: every command, the reasoning behind it, and dead-ends explored. This is what a peer reviews.

### Finding severity scale

| Severity | CVSS band | Meaning |
|----------|-----------|---------|
| Critical | 9.0–10.0 | Full compromise, trivially exploitable |
| High | 7.0–8.9 | Significant impact or easy exploitation |
| Medium | 4.0–6.9 | Meaningful risk, conditions apply |
| Low | 0.1–3.9 | Limited impact / defense-in-depth |
| Info | — | Hygiene, no direct exploit |

### Remediation framing

Every finding closes with: **root cause → recommended fix → references**. A finding without a remediation is an incomplete finding.

---

## Phase 7 — Cleanup

- Remove uploaded tooling / shells from the target.
- Note any artifacts intentionally left (and why) for the report's appendix.
