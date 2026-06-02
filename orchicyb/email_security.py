import dns.resolver

from .utils import domain_from_url

COMMON_DKIM_SELECTORS = [
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "s1",
    "dkim",
    "mail",
]


def _txt_records(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=5)
        records = []
        for answer in answers:
            records.append(
                "".join(
                    part.decode() if isinstance(part, bytes) else str(part)
                    for part in answer.strings
                )
            )
        return records
    except Exception:
        return []


def check_email_security(domain_or_url: str, dkim_selector: str | None = None) -> dict:
    domain = (
        domain_from_url(domain_or_url)
        if "://" in domain_or_url
        else domain_or_url.strip().lower()
    )

    txt = _txt_records(domain)
    spf = [record for record in txt if record.lower().startswith("v=spf1")]

    dmarc_records = _txt_records(f"_dmarc.{domain}")
    dmarc = [record for record in dmarc_records if record.lower().startswith("v=dmarc1")]

    dkim_found = []
    selectors_tried = []
    if dkim_selector:
        selectors_tried = [dkim_selector]
    else:
        selectors_tried = COMMON_DKIM_SELECTORS

    matched_selector = None
    for selector in selectors_tried:
        dkim_name = f"{selector}._domainkey.{domain}"
        dkim_records = _txt_records(dkim_name)
        dkim = [
            record
            for record in dkim_records
            if "dkim" in record.lower() or "p=" in record.lower()
        ]
        if dkim:
            dkim_found = dkim
            matched_selector = selector
            break

    score = 0
    recommendations = []

    if spf:
        score += 35
        if "+all" in spf[0].lower():
            recommendations.append(
                "SPF uses +all (permits any sender) — tighten to ~all or -all."
            )
    else:
        recommendations.append(
            "No SPF record — publish v=spf1 at the domain apex to authorize mail senders."
        )

    if dmarc:
        score += 45
        policy = dmarc[0].lower()
        if "p=reject" in policy:
            score += 15
        elif "p=quarantine" in policy:
            score += 10
        elif "p=none" in policy:
            recommendations.append(
                "DMARC policy is p=none — move toward quarantine or reject after monitoring."
            )
        if "rua=" not in policy and "ruf=" not in policy:
            recommendations.append(
                "DMARC has no aggregate/forensic reporting address — add rua= for visibility."
            )
    else:
        recommendations.append(
            "No DMARC record — add _dmarc TXT with v=DMARC1 and a policy (start with p=none)."
        )

    if dkim_found:
        score += 20
    else:
        recommendations.append(
            "DKIM not found for common selectors — verify your mail provider's selector."
        )

    return {
        "domain": domain,
        "spf": spf,
        "dmarc": dmarc,
        "dkim_selector": matched_selector or (dkim_selector or "default"),
        "selectors_checked": selectors_tried,
        "dkim": dkim_found,
        "score": min(score, 100),
        "recommendations": recommendations,
    }
