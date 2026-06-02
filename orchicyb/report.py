from pathlib import Path
from datetime import datetime, timezone

from fpdf import FPDF

from .risk import calculate_risk


def generate_reports(
    target: str,
    output_dir: str = "reports",
    fmt: str = "md",
) -> list[Path]:
    data = calculate_risk(target)
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    stem = f"orchicyb_report_{data['target'].replace('.', '_')}"
    paths: list[Path] = []

    if fmt in ("md", "both"):
        paths.append(_write_markdown(data, output_dir, stem))
    if fmt in ("pdf", "both"):
        paths.append(_write_pdf(data, output_dir, stem))

    return paths


def generate_markdown_report(target: str, output_dir: str = "reports") -> Path:
    return generate_reports(target, output_dir, fmt="md")[0]


def generate_pdf_report(target: str, output_dir: str = "reports") -> Path:
    return generate_reports(target, output_dir, fmt="pdf")[0]


def _write_markdown(data: dict, output_dir: str, stem: str) -> Path:
    path = Path(output_dir) / f"{stem}.md"
    headers = data["website_security"]
    dns = data["dns_visibility"]
    email = data["email_security"]
    tls = data["tls"]

    content = f"""# orchicyb Digital Risk Report

**Target:** `{data['target']}`  
**Generated:** {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}  
**Overall Score:** {data['overall_score']}/100  
**Risk Level:** {data['risk_level']}

---

## Executive summary

| Category | Score |
|----------|------:|
| Website security | {headers.get('score', 0)}/100 |
| TLS certificate | {tls.get('score', 0)}/100 |
| DNS visibility | {dns.get('score', 0)}/100 |
| Email authentication | {email.get('score', 0)}/100 |

---

## Website security headers

**Score:** {headers.get('score', 0)}/100  
**Reachable:** {headers.get('reachable')}  
**Status code:** {headers.get('status_code')}  
**Final URL:** {headers.get('final_url') or '-'}  
**HTTP to HTTPS redirect:** {_fmt_bool(headers.get('https_redirect'))}

### Present headers

{_list_dict(headers.get('present', {}))}

### Missing headers

{_list(headers.get('missing', []))}

---

## TLS certificate

**Score:** {tls.get('score', 0)}/100  
**Reachable:** {tls.get('reachable')}  
**Protocol:** {tls.get('protocol') or '-'}  
**Issuer:** {tls.get('issuer') or '-'}  
**Subject:** {tls.get('subject') or '-'}  
**Expires:** {tls.get('expires') or '-'}  
**Days remaining:** {tls.get('days_remaining') if tls.get('days_remaining') is not None else '-'}

---

## DNS visibility

**Score:** {dns.get('score', 0)}/100

{_dns_records(dns.get('records', {}))}

---

## Email authentication

**Score:** {email.get('score', 0)}/100

| Control | Status |
|---------|--------|
| SPF | {'Found' if email.get('spf') else 'Missing'} |
| DMARC | {'Found' if email.get('dmarc') else 'Missing'} |
| DKIM selector | {email.get('dkim_selector')} |
| DKIM | {'Found' if email.get('dkim') else 'Not found'} |

### SPF record

```
{email.get('spf', ['-'])[0] if email.get('spf') else '-'}
```

### DMARC record

```
{email.get('dmarc', ['-'])[0] if email.get('dmarc') else '-'}
```

---

## Prioritized recommendations

{_numbered(data.get('recommendations', []))}

---

## Disclaimer

This report supports defensive awareness and **authorized** security review. Validate findings manually before operational or business decisions.
"""
    path.write_text(content, encoding="utf-8")
    return path


def _write_pdf(data: dict, output_dir: str, stem: str) -> Path:
    path = Path(output_dir) / f"{stem}.pdf"
    headers = data["website_security"]
    dns = data["dns_visibility"]
    email = data["email_security"]
    tls = data["tls"]
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 10, "orchicyb Digital Risk Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.ln(2)

    _pdf_kv(pdf, "Target", data["target"])
    _pdf_kv(pdf, "Generated", generated)
    _pdf_kv(pdf, "Overall score", f"{data['overall_score']}/100")
    _pdf_kv(pdf, "Risk level", data["risk_level"])

    _pdf_heading(pdf, "Executive summary")
    _pdf_kv(pdf, "Website security", f"{headers.get('score', 0)}/100")
    _pdf_kv(pdf, "TLS certificate", f"{tls.get('score', 0)}/100")
    _pdf_kv(pdf, "DNS visibility", f"{dns.get('score', 0)}/100")
    _pdf_kv(pdf, "Email authentication", f"{email.get('score', 0)}/100")

    _pdf_heading(pdf, "Website security headers")
    _pdf_kv(pdf, "Score", f"{headers.get('score', 0)}/100")
    _pdf_kv(pdf, "Reachable", str(headers.get("reachable")))
    _pdf_kv(pdf, "Status code", str(headers.get("status_code")))
    _pdf_kv(pdf, "Final URL", headers.get("final_url") or "-")
    _pdf_kv(pdf, "HTTP to HTTPS", _fmt_bool(headers.get("https_redirect")))
    _pdf_subheading(pdf, "Present headers")
    for name, value in headers.get("present", {}).items():
        _pdf_bullet(pdf, f"{name}: {value}")
    if not headers.get("present"):
        _pdf_bullet(pdf, "None")
    _pdf_subheading(pdf, "Missing headers")
    for name in headers.get("missing", []):
        _pdf_bullet(pdf, name)
    if not headers.get("missing"):
        _pdf_bullet(pdf, "None")

    _pdf_heading(pdf, "TLS certificate")
    _pdf_kv(pdf, "Score", f"{tls.get('score', 0)}/100")
    _pdf_kv(pdf, "Reachable", str(tls.get("reachable")))
    _pdf_kv(pdf, "Protocol", tls.get("protocol") or "-")
    _pdf_kv(pdf, "Issuer", tls.get("issuer") or "-")
    _pdf_kv(pdf, "Subject", tls.get("subject") or "-")
    _pdf_kv(pdf, "Expires", tls.get("expires") or "-")
    days = tls.get("days_remaining")
    _pdf_kv(pdf, "Days remaining", str(days) if days is not None else "-")

    _pdf_heading(pdf, "DNS visibility")
    _pdf_kv(pdf, "Score", f"{dns.get('score', 0)}/100")
    for record_type, values in dns.get("records", {}).items():
        _pdf_subheading(pdf, record_type)
        if values:
            for value in values[:8]:
                _pdf_bullet(pdf, value)
            if len(values) > 8:
                _pdf_bullet(pdf, f"... and {len(values) - 8} more")
        else:
            _pdf_bullet(pdf, "No records")

    _pdf_heading(pdf, "Email authentication")
    _pdf_kv(pdf, "Score", f"{email.get('score', 0)}/100")
    _pdf_kv(pdf, "SPF", "Found" if email.get("spf") else "Missing")
    _pdf_kv(pdf, "DMARC", "Found" if email.get("dmarc") else "Missing")
    _pdf_kv(pdf, "DKIM selector", str(email.get("dkim_selector")))
    _pdf_kv(pdf, "DKIM", "Found" if email.get("dkim") else "Not found")
    if email.get("spf"):
        _pdf_subheading(pdf, "SPF record")
        _pdf_body(pdf, email["spf"][0])
    if email.get("dmarc"):
        _pdf_subheading(pdf, "DMARC record")
        _pdf_body(pdf, email["dmarc"][0])

    _pdf_heading(pdf, "Prioritized recommendations")
    recs = data.get("recommendations", [])
    if recs:
        for i, item in enumerate(recs[:12], 1):
            _pdf_body(pdf, f"{i}. {_sanitize_pdf(item)}")
    else:
        _pdf_body(pdf, "No critical recommendations - maintain current controls.")

    _pdf_heading(pdf, "Disclaimer")
    _pdf_body(
        pdf,
        "This report supports defensive awareness and authorized security review. "
        "Validate findings manually before operational or business decisions.",
    )

    pdf.output(str(path))
    return path


def _pdf_heading(pdf: FPDF, text: str) -> None:
    pdf.ln(6)
    pdf.set_font("Helvetica", "B", 13)
    pdf.cell(0, 8, _sanitize_pdf(text), new_x="LMARGIN", new_y="NEXT")


def _pdf_subheading(pdf: FPDF, text: str) -> None:
    pdf.ln(3)
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, _sanitize_pdf(text), new_x="LMARGIN", new_y="NEXT")


def _pdf_kv(pdf: FPDF, key: str, value: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, f"{_sanitize_pdf(key)}:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(pdf.epw, 6, _sanitize_pdf(str(value)))


def _pdf_bullet(pdf: FPDF, text: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(pdf.epw, 5, f"- {_sanitize_pdf(text)}")


def _pdf_body(pdf: FPDF, text: str) -> None:
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Helvetica", "", 10)
    pdf.multi_cell(pdf.epw, 5, _sanitize_pdf(text))


def _sanitize_pdf(text: str) -> str:
    return (
        text.replace("\u2014", "-")
        .replace("\u2013", "-")
        .replace("\u2022", "-")
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


def _fmt_bool(value) -> str:
    if value is True:
        return "Yes"
    if value is False:
        return "No"
    return "Unknown"


def _list(items: list[str]) -> str:
    if not items:
        return "- None"
    return "\n".join(f"- {item}" for item in items)


def _list_dict(items: dict) -> str:
    if not items:
        return "- None"
    return "\n".join(f"- **{key}:** `{value}`" for key, value in items.items())


def _dns_records(records: dict) -> str:
    lines = []
    for record_type, values in records.items():
        lines.append(f"### {record_type}")
        lines.append(_list(values))
        lines.append("")
    return "\n".join(lines)


def _numbered(items: list[str]) -> str:
    if not items:
        return "No critical recommendations - maintain current controls."
    return "\n".join(f"{i}. {item}" for i, item in enumerate(items[:12], 1))
