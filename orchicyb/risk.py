from .headers import check_headers
from .dns_check import lookup_dns
from .email_security import check_email_security
from .tls_check import check_tls
from .utils import domain_from_url, risk_level


def calculate_risk(domain_or_url: str) -> dict:
    domain = domain_from_url(domain_or_url)
    headers = check_headers(domain)
    dns = lookup_dns(domain)
    email = check_email_security(domain)
    tls = check_tls(domain)

    scores = [
        headers.get("score", 0),
        dns.get("score", 0),
        email.get("score", 0),
        tls.get("score", 0),
    ]
    overall = int(sum(scores) / len(scores))

    recommendations = []
    for section in (headers, dns, email, tls):
        recommendations.extend(section.get("recommendations", []))

    return {
        "target": domain,
        "website_security": headers,
        "dns_visibility": dns,
        "email_security": email,
        "tls": tls,
        "overall_score": overall,
        "risk_level": risk_level(overall),
        "recommendations": recommendations[:12],
    }
