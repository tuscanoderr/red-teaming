# Penetration Test Report — <TARGET NAME>

| | |
|---|---|
| **Target** | `<hostname>` / `<IP>` |
| **Platform** | TryHackMe — <room URL> |
| **Assessment type** | Black-box network/web penetration test |
| **Date** | <YYYY-MM-DD> |
| **Tester** | <you> |
| **Overall risk** | 🔴 Critical / 🟠 High / 🟡 Medium |

---

## 1. Executive summary

A short, non-technical paragraph: what was assessed, the headline result (e.g. "full administrative compromise was achieved"), and the single most important thing to fix. Written for someone who will not read past this section.

**Key outcomes**

- Initial access obtained via `<vector>`.
- Privileges escalated to `<root/SYSTEM>` via `<vector>`.
- `<n>` findings: `<x>` Critical, `<y>` High, `<z>` Medium.

---

## 2. Finding register

| ID | Finding | Severity | CVSS |
|----|---------|----------|------|
| F-01 | <title> | Critical | 9.8 |
| F-02 | <title> | High | 8.1 |
| F-03 | <title> | Medium | 5.3 |

---

## 3. Findings (detail)

### F-01 — <Finding title>

- **Severity:** Critical (CVSS 9.8 — `CVSS:3.1/AV:N/AC:L/...`)
- **Affected component:** `<service / endpoint / version>`
- **Description:** What the weakness is, in plain terms.
- **Evidence:**

  ```
  <command and output proving the finding>
  ```
  ![evidence](./assets/<screenshot>.png)

- **Impact:** What an attacker achieves. Tie to confidentiality/integrity/availability.
- **Remediation:**
  - <concrete fix>
  - <config change / patch / version>
- **References:** CVE-XXXX-XXXX, vendor advisory, exploit-db ID.

> Repeat the block for each finding.

---

## 4. Attack narrative (summary)

A paragraph-level chain: `recon → foothold → escalation → compromise`, so a reader sees how the findings combine into full compromise.

---

## 5. Remediation roadmap

| Priority | Action | Addresses |
|----------|--------|-----------|
| Immediate | <patch / disable> | F-01 |
| Short-term | <config hardening> | F-02 |
| Hygiene | <process change> | F-03 |

---

## 6. Appendix

- Full tool output of note
- Scope & authorization statement
