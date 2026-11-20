# Walkthrough — <TARGET NAME>

> Technical narrative. Every command, why it was run, and what it told us. Dead-ends included — they show methodology.

**Target:** `<IP>`  ·  **Room:** <url>  ·  **Date:** <YYYY-MM-DD>

---

## Phase 1 — Recon & enumeration

### Full port scan

```bash
nmap -p- --min-rate 10000 -T4 $IP -oN scans/01-allports.txt
```

_What we expected / what we found:_

### Service scan

```bash
nmap -p <ports> -sC -sV -oN scans/02-services.txt $IP
```

| Port | Service | Version | Notes / hypothesis |
|------|---------|---------|--------------------|
| | | | |

### Service enumeration

_(web dirbusting, SMB shares, etc. — with the reasoning for each)_

---

## Phase 2 — Vulnerability analysis

_Version → known vuln mapping, and how it was validated._

---

## Phase 3 — Foothold

_The exploit, why it works, and proof of the shell._

```bash

```

---

## Phase 4 — Privilege escalation

```bash
id; sudo -l
```

_The escalation path, step by step._

---

## Phase 5 — Proof

```bash
cat /root/root.txt   # or equivalent objective
```

---

## Lessons / notes

- What was the key insight?
- What would have made this faster?
- What would stop a real attacker here (feeds the remediation section)?
