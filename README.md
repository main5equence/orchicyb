# orchicyb

**Digital Risk & OSINT Toolkit** - defensive domain assessment from your terminal.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![CLI](https://img.shields.io/badge/interface-terminal-green.svg)](#usage)

orchicyb helps individuals **baseline digital exposure** for domains they own or are authorized to assess. It combines HTTP security headers, TLS certificate health, DNS visibility, and email authentication (SPF / DMARC / DKIM) into a single workflow - with scored output, actionable recommendations, and exportable **Markdown** and **PDF** reports.

> **Authorized use only.** orchicyb is built for defensive security, awareness, and compliance-style reviews - not for attacking third-party systems without permission.

<img width="1461" height="926" alt="Zrzut ekranu 2026-06-02 151517" src="https://github.com/user-attachments/assets/b66bc470-c33f-4c97-8393-255ad456c26a" />


---

## Table of contents

- [Why orchicyb](#why-orchicyb)
- [Features](#features)
- [What you can assess](#what-you-can-assess)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Commands](#commands)
- [Scoring model](#scoring-model)
- [Reports](#reports)
- [Example output](#example-output)
- [Project structure](#project-structure)
- [Ethics & legal use](#ethics--legal-use)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

---

## Why orchicyb

Many individuals need a **lightweight, explainable** way to answer:

- Are our security headers and HTTPS behavior reasonable?
- Is our TLS certificate valid and expiring soon?
- Is our DNS footprint complete and intentional?
- Do we have baseline email spoofing protections (SPF, DMARC, DKIM)?

orchicyb fills the gap between manual checklist reviews and heavy enterprise scanners. It is:

- **Fast** - results in seconds from the CLI
- **Readable** - Rich tables, color-coded scores, clear recommendations
- **Shareable** - Markdown and PDF reports for stakeholders
- **Transparent** - open-source logic you can inspect and extend

---

## Features

| Command | Purpose |
|---------|---------|
| `scan` | Full assessment: headers, TLS, DNS, email, overall score |
| `headers` | Security headers (HSTS, CSP, X-Frame-Options, COOP/CORP, …) + HTTP→HTTPS redirect |
| `tls` | Certificate issuer, expiry, days remaining, negotiated protocol |
| `dns` | A, AAAA, MX, NS, TXT, CAA, SOA records |
| `email` | SPF, DMARC, DKIM (auto-detects common selectors) |
| `risk` | Weighted digital risk score across all categories |
| `report` | Export **Markdown** (`.md`), **PDF** (`.pdf`), or **both** |

### Technical highlights

- Weighted scoring per category with overall risk level (`Low` → `Critical`)
- Prioritized remediation recommendations (up to 12 items in reports)
- DKIM selector discovery (`google`, `selector1`, `default`, …)
- DMARC policy hints (`p=none`, missing `rua=`, etc.)
- SPF quality warnings (e.g. permissive `+all`)
- DNS guidance (missing MX, CAA, apex SPF)
- Professional terminal UX (banner, command table, progress spinner)

---

## What you can assess

orchicyb evaluates **domains and web hosts you are allowed to test**.

| Input type | Example | What is checked |
|------------|---------|-----------------|
| Apex domain | `example.com` | DNS, email auth, TLS on `:443`, HTTPS headers |
| Subdomain | `app.example.com` | Same checks for that host |
| Full URL | `https://example.com/login` | Domain-level checks; `headers` uses the **exact URL** you provide |

### Good use cases

- Corporate websites and marketing pages
- Customer-facing web applications (with authorization)
- Mail-enabled business domains
- Pre-launch or post-change security baselines
- Security awareness demos on **owned** lab domains

### Out of scope

- Unauthorized third-party scanning
- Social media profiles or personal accounts
- Full-site crawlers / penetration testing
- Exploitation, brute force, or vulnerability chaining

See [SECURITY.md](SECURITY.md) for responsible use and vulnerability reporting.

---

## Installation

### Requirements

- Python **3.10+**
- Network access for DNS and HTTPS checks

### From source (recommended)

```bash
git clone https://github.com/YOUR_USERNAME/orchicyb.git
cd orchicyb

python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows (PowerShell)
.venv\Scripts\activate

pip install -e .
```

### Verify

```bash
orchicyb --version
orchicyb
```

---

## Quick start

```bash
# Full assessment (recommended entry point)
orchicyb scan yourdomain.com

# Export PDF report for stakeholders
orchicyb report yourdomain.com -f pdf --output reports

# Inspect a specific URL's headers
orchicyb headers https://yourdomain.com/admin
```

---

## Commands

### `orchicyb` (no args)

Shows banner, project description, command table, and quick-start examples.

### `orchicyb scan <target>`

Runs all checks and prints a summary table plus recommendations.

```bash
orchicyb scan example.com
orchicyb scan https://app.example.com
```

### `orchicyb headers <target>`

```bash
orchicyb headers example.com
orchicyb headers https://example.com/path
```

### `orchicyb tls <domain>`

```bash
orchicyb tls example.com
```

### `orchicyb dns <domain>`

```bash
orchicyb dns example.com
```

### `orchicyb email <domain>`

```bash
orchicyb email example.com
orchicyb email example.com --selector google
```

### `orchicyb risk <target>`

```bash
orchicyb risk example.com
```

### `orchicyb report <target>`

| Flag | Description |
|------|-------------|
| `--output`, `-o` | Output directory (default: `reports`) |
| `--format`, `-f` | `md` (default), `pdf`, or `both` |

```bash
orchicyb report example.com
orchicyb report example.com -f pdf
orchicyb report example.com -f both --output reports
```

---

## Scoring model

Scores are **indicative baselines**, not certifications. Each category is scored 0–100; the overall score is the arithmetic mean of:

1. Website security (HTTP headers + HTTPS redirect behavior)
2. TLS certificate (validity, expiry horizon, protocol)
3. DNS visibility (record presence and mail-related signals)
4. Email authentication (SPF, DMARC policy, DKIM discovery)

| Overall score | Risk level |
|---------------|------------|
| 85–100 | Low |
| 65–84 | Moderate |
| 40–64 | High |
| 0–39 | Critical |

Always validate results manually before operational or business decisions.

---

## Reports

Generated files are written to the output directory (default: `reports/`):

```
reports/orchicyb_report_example_com.md
reports/orchicyb_report_example_com.pdf
```

Report sections:

1. Executive summary
2. Website security headers
3. TLS certificate
4. DNS visibility
5. Email authentication
6. Prioritized recommendations
7. Disclaimer

---

## Example output

```bash
orchicyb scan example.com
```

```text
Assessment: example.com
┌──────────────────────┬─────────┐
│ Website security     │  75/100 │
│ TLS certificate      │ 100/100 │
│ DNS visibility       │  85/100 │
│ Email authentication │  60/100 │
│ Overall              │  80/100 │
│ Risk level           │ Moderate │
└──────────────────────┴─────────┘

Recommendations
  - HTTP does not redirect to HTTPS ...
  - Enable HSTS ...
```

---

## Project structure

```
orchicyb/
├── orchicyb/
│   ├── cli.py           # Click CLI entrypoint
│   ├── banner.py        # Welcome screen & help
│   ├── headers.py       # HTTP security headers
│   ├── tls_check.py     # TLS / certificate checks
│   ├── dns_check.py     # DNS record lookups
│   ├── email_security.py# SPF, DMARC, DKIM
│   ├── risk.py          # Aggregated risk scoring
│   ├── report.py        # Markdown & PDF export
│   └── utils.py         # Shared helpers
├── pyproject.toml
├── requirements.txt
├── LICENSE              # MIT
├── README.md
└── SECURITY.md
```

---

## Ethics & legal use

orchicyb must only be used:

- On domains and infrastructure **you own**, or
- Where you have **explicit written authorization** from the owner

Unauthorized scanning may violate computer misuse laws, contracts, and platform policies. You are responsible for how you use this tool.

---

## Contributing

Contributions are welcome via pull requests. Please:

1. Keep changes focused and defensive in nature
2. Do not add offensive or unauthorized scanning capabilities
3. Run manual checks before submitting (`orchicyb scan example.com`)
4. Follow existing code style and CLI patterns

---

## Security

If you discover a **vulnerability in orchicyb itself** (not in scan targets), see [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## License

MIT License - Copyright (c) 2026 Dominika Jakubek. See [LICENSE](LICENSE).
