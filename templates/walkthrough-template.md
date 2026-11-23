# Walkthrough — <TARGET NAME>

> Technical narrative, organized by the six-phase methodology: **Recon → Enumeration → Vulnerability Analysis → Exploitation → Post-Exploitation → Reporting**. Every command, and the reasoning behind it.

**Target:** `<IP>`  ·  **Room:** <url>  ·  **Date:** <YYYY-MM-DD>  ·  **Result:** <foothold/root/DA>

---

## Phase 1 — Reconnaissance

_What is the target and what is exposed?_

```bash
export IP=<TARGET_IP>
ping -c 3 $IP
nmap -p- --min-rate 10000 -T4 $IP -oN allports.txt
```

_Open ports + first hypothesis of the host's role._

---

## Phase 2 — Enumeration

_What exactly is each service, and what detail can we extract?_

```bash
nmap -p <ports> -sC -sV -oN services.txt $IP
```

| Port | Service | Version | Notes / hypothesis |
|------|---------|---------|--------------------|
| | | | |

_Service-specific enumeration (web dirbusting, SMB shares, user enum, etc.)._

---

## Phase 3 — Vulnerability Analysis

_Which detail is a weakness, and how severe?_

- Version/config → known vuln mapping (CVE / advisory).
- Validation approach.
- Provisional CVSS severity and the chosen attack path.

---

## Phase 4 — Exploitation

_Prove the weakness by gaining access._

```bash

```

_The exploit, why it works, proof of the foothold, and the named initial access vector._

---

## Phase 5 — Post-Exploitation

_How far does the access reach?_

```bash
id; whoami; hostname; sudo -l
```

_Privilege escalation, credential looting, lateral movement, and capture of objectives (flags). Note cleanup._

---

## Phase 6 — Reporting (risk translation)

_What does this mean for the business, and how is it fixed?_

See [`report.md`](./report.md) for findings (CVSS), impact, and remediation. State the headline risk and the key drivers here.
