# Assessment Methodology

Every engagement in this repository follows the same six-phase process, aligned to the **Penetration Testing Execution Standard (PTES)** and, for web targets, the **OWASP Web Security Testing Guide**. The phases are deliberately explicit so any reader can follow the same path and reach the same result — the hallmark of a disciplined assessment versus ad-hoc hacking.

> **Authorization.** All testing is performed only against machines explicitly authorized within the TryHackMe platform, over its isolated VPN. Nothing outside the single assigned target is touched.

The six phases, applied to every engagement:

| # | Phase | Question it answers |
|---|-------|---------------------|
| 1 | **Reconnaissance** | What is the target and what is exposed? |
| 2 | **Enumeration** | What exactly is each exposed service, and what detail can we extract? |
| 3 | **Vulnerability Analysis** | Which of those details is a *weakness*, and how severe? |
| 4 | **Exploitation** | Can we prove the weakness by gaining access? |
| 5 | **Post-Exploitation** | How far does that access reach — escalation, lateral movement, impact? |
| 6 | **Reporting (risk translation)** | What does this mean for the business, and how is it fixed? |

---

## Phase 1 — Reconnaissance

Establish what the target is and what it exposes. Breadth first, no assumptions.

```bash
ping -c 3 $IP                                             # alive? (TTL hints at OS)
nmap -p- --min-rate 10000 -T4 $IP -oN scans/allports.txt # every open port
```

Output: a confirmed list of open ports and a first hypothesis of the host's role (web server, domain controller, etc.).

## Phase 2 — Enumeration

Turn open ports into detailed, actionable facts. This is where the majority of engagement time lives — a missed detail is a missed finding.

```bash
nmap -p <ports> -sC -sV -oN scans/services.txt $IP       # versions + default scripts
```

Then drill into each service with the right tool:

| Service | Tooling / technique |
|---------|---------------------|
| HTTP/HTTPS | `whatweb`, `gobuster`/`feroxbuster`, CMS + **version** fingerprint, manual review |
| SMB (139/445) | `enum4linux(-ng)`, `crackmapexec`/`nxc`, `smbclient`, null-session checks |
| Kerberos/LDAP (88/389) | domain name, user enumeration (`kerbrute`), AS-REP-roastable accounts |
| FTP/SSH/DNS | banners, anonymous access, zone transfers, known-CVE mapping |

Output: the exact software, versions, accounts, shares, and configuration that make up the attack surface.

## Phase 3 — Vulnerability Analysis

Decide which enumerated facts are **weaknesses**, confirm them, and rank them.

- Map versions/configs to known vulnerabilities (CVE, exploit-db, vendor advisories).
- **Validate before trusting** — scanner output is a lead, not a finding.
- Assign a provisional severity with **CVSS v3.1** so prioritization is defensible.

Output: a short, ranked list of credible attack paths — the decision point that separates a methodical tester from a tool-runner.

## Phase 4 — Exploitation

Prove the weakness by gaining access. Lowest-noise, highest-reliability path first; understand *why* it works, and capture evidence at the moment of compromise (command + output + timestamp).

Output: the **initial access vector** — the primary finding — and a foothold.

## Phase 5 — Post-Exploitation

Measure how far the foothold reaches. This is where impact is demonstrated.

```bash
id; whoami; hostname; sudo -l            # situational awareness
./linpeas.sh | tee loot/linpeas.txt      # automated triage (winPEAS on Windows)
```

Covers: privilege escalation, credential looting, lateral movement, and capture of objectives (flags / proof). Clean up afterward (remove uploaded tooling/shells; note anything intentionally left).

Output: the full extent of compromise, with proof.

## Phase 6 — Reporting (risk translation)

Convert the technical chain into business risk and remediation. Each engagement produces two documents:

1. **`report.md`** — the formal deliverable a client reads: executive summary, a finding register (each finding with **severity, evidence, impact, and remediation**), the attack narrative, and a prioritized remediation roadmap.
2. **`walkthrough.md`** — the technical narrative a peer reviews: every command and the reasoning behind it, organized by these six phases.

**Translating to risk** means every finding answers: *what is the business impact* (confidentiality/integrity/availability), *how likely/easy is exploitation*, and *what is the concrete fix*. A finding without a remediation is incomplete.

### Severity scale

| Severity | CVSS band | Meaning |
|----------|-----------|---------|
| Critical | 9.0–10.0 | Full compromise, trivially exploitable |
| High | 7.0–8.9 | Significant impact or easy exploitation |
| Medium | 4.0–6.9 | Meaningful risk, conditions apply |
| Low | 0.1–3.9 | Limited impact / defense-in-depth |
| Info | — | Hygiene, no direct exploit |
