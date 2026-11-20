# Offensive Security Lab Portfolio

A documented collection of penetration-testing engagements performed against intentionally vulnerable lab machines on [TryHackMe](https://tryhackme.com). Each engagement is written up as a structured assessment — reconnaissance, enumeration, exploitation, post-exploitation, and remediation — mirroring the methodology and reporting standard of a professional VAPT engagement.

> **Scope & authorization.** All testing documented here was performed exclusively against machines I am explicitly authorized to attack within the TryHackMe platform, over its isolated VPN. No system outside that authorized lab scope was touched. These writeups are for education and demonstration of methodology.

---

## Why this repo exists

To demonstrate, with evidence, the full lifecycle of a technical security assessment: how a target is mapped, how findings are validated (not just scanner output), how access is chained from foothold to full compromise, and — critically — how each finding maps to concrete, prioritized remediation.

## Methodology

Every engagement follows the phased approach documented in **[METHODOLOGY.md](./METHODOLOGY.md)**, aligned to PTES (Penetration Testing Execution Standard) and, for web targets, the OWASP Testing Guide.

## Engagements

| # | Target | Platform | Difficulty | Key techniques | Status |
|---|--------|----------|------------|----------------|--------|
| 01 | [Daily Bugle](./engagements/daily-bugle/) | Linux (CentOS 7) | Hard | Joomla SQLi (CVE-2017-8917), hash cracking, template RCE, password reuse, `sudo yum` privesc | ✅ Rooted |
| 02 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | 🔜 Planned |
| 03 | _TBD_ | _TBD_ | _TBD_ | _TBD_ | 🔜 Planned |

Each engagement lives in `engagements/<name>/` and contains:

- `report.md` — the formal assessment report (exec summary → findings → remediation)
- `walkthrough.md` — the step-by-step technical narrative with commands and reasoning
- `commands.md` — a clean, reproducible reference of every command used, in order
- `assets/` — screenshots and captured evidence
- `loot/` — extracted artifacts (hashes, configs) where safe to retain

## Repository layout

```
.
├── README.md                 # This file
├── METHODOLOGY.md            # The repeatable assessment process
├── templates/
│   ├── report-template.md    # Formal report skeleton
│   └── walkthrough-template.md
└── engagements/
    └── <target-name>/
        ├── report.md
        ├── walkthrough.md
        ├── assets/
        └── loot/
```

## About

Maintained as a professional skills portfolio. Findings, severities, and remediation guidance reflect real-world assessment practice applied to lab targets.
