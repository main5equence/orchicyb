# Security Policy

## Our security stance

orchicyb is a **defensive** command-line tool for authorized domain and web posture assessment. It is designed to help owners and permitted assessors understand exposure — not to facilitate unauthorized access, harassment, or attacks against third parties.

By using orchicyb, you agree to comply with applicable laws, contracts, and platform policies. **You are solely responsible for obtaining permission before scanning any target.**

---

## Supported versions

Security fixes are provided for the latest release on the default branch.

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes       |
| < 0.2   | No        |

---

## Reporting a vulnerability in orchicyb

If you believe you have found a **security vulnerability in the orchicyb software** (the CLI, dependencies as bundled, report generation, or repository artifacts), please report it responsibly.

**Do not** open a public GitHub issue for sensitive security reports.

### How to report

1. Email or message the maintainer privately (replace with your contact when publishing):

   **security@your-domain.example** — or open a private GitHub Security Advisory once the repository exists.

2. Include as much detail as possible:

   - Affected version (`orchicyb --version`)
   - Platform (Windows / macOS / Linux)
   - Steps to reproduce
   - Impact assessment (confidentiality, integrity, availability)
   - Proof of concept if available (minimal, non-destructive)

3. Allow reasonable time for triage and remediation before public disclosure.

### What we consider in scope

Examples of in-scope reports for **this project**:

- Remote code execution via malicious scan targets or report content
- Path traversal or arbitrary file write when exporting reports
- Credential leakage through logs, temp files, or error messages
- Unsafe deserialization or command injection in orchicyb code
- Dependency vulnerabilities with demonstrated exploitability in orchicyb’s usage

### Out of scope

The following are **not** accepted as vulnerabilities in orchicyb:

- Weak security posture of **third-party domains you scan** (that is the intended output of the tool)
- Issues on targets you do not own and were not authorized to test
- Social engineering, physical access, or denial-of-service against remote sites
- Missing features (e.g. full pentest coverage, CVE scanning, subdomain brute force)
- Reports that DNS/HTTP checks reveal public information about a domain
- User misconfiguration (scanning without permission)

---

## Responsible use requirements

When operating orchicyb, you must:

| Requirement | Detail |
|-------------|--------|
| **Authorization** | Scan only domains, hosts, and URLs you own or are explicitly permitted to assess |
| **Proportionality** | Use the minimum checks needed for your purpose |
| **Data handling** | Treat reports as potentially sensitive; restrict storage and sharing |
| **No abuse** | Do not use orchicyb to harass, defraud, or disrupt services |
| **Accurate representation** | Do not market the tool as a “hacking” or “breach” utility |

### Prohibited uses

- Scanning government, education, healthcare, or corporate assets **without written approval**
- Using results to attempt exploitation, credential stuffing, or phishing
- Publishing scan results that identify third parties without consent
- Circumventing rate limits, robots.txt, or contractual restrictions on automated access
- Any activity illegal in your jurisdiction

---

## Data & privacy

orchicyb performs **live network queries** against the target you specify:

- HTTP(S) requests (headers, redirects)
- DNS lookups (multiple record types)
- TLS handshakes (certificate metadata)

Data is processed **locally** on your machine. Reports are written only to paths you choose (default: `reports/`). No telemetry is sent to orchicyb maintainers by default.

**Your obligations:**

- Do not commit generated reports to public repositories if they contain client data
- Add `reports/` to `.gitignore` (already included in this project)
- Rotate or redact secrets if they appear in HTTP headers or TXT records

---

## Safe defaults & hardening tips

For operators publishing or deploying orchicyb:

1. Run from a dedicated virtual environment (`python -m venv .venv`)
2. Pin dependencies in production forks (`pip freeze` or lockfile)
3. Review third-party modules (`requests`, `dnspython`, `fpdf2`, `rich`) periodically
4. Restrict file permissions on the `reports/` directory
5. Use least-privilege OS accounts when running scheduled scans in CI

---

## Disclosure timeline

We aim to:

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 5 business days |
| Triage | Within 10 business days |
| Fix or mitigation plan | Depends on severity; critical issues prioritized |
| Coordinated disclosure | After patch availability, by mutual agreement |

We appreciate researchers who act in good faith and respect user safety.

---

## Security-related dependencies

orchicyb relies on well-known Python packages. Keep them updated:

```bash
pip install -U pip
pip install -e .
```

Report supply-chain concerns if a bundled dependency is used in an unsafe way **within orchicyb’s code paths**.

---

## Legal notice

This document does not constitute legal advice. Consult qualified counsel regarding authorized security testing in your country and industry.

---

## Contact

When the repository is public, enable **GitHub Private Vulnerability Reporting** (Settings → Security → Private vulnerability reporting) and link it here.

Until then, contact the project owner directly through your preferred private channel.
