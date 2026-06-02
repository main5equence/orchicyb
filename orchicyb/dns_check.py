import dns.resolver

from .utils import domain_from_url

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CAA", "SOA"]

RECORD_WEIGHTS = {
    "A": 15,
    "AAAA": 10,
    "MX": 20,
    "NS": 15,
    "TXT": 20,
    "CAA": 10,
    "SOA": 10,
}


def lookup_dns(domain_or_url: str) -> dict:
    domain = domain_from_url(domain_or_url) if "://" in domain_or_url else domain_or_url.strip().lower()
    result = {
        "domain": domain,
        "records": {},
        "score": 0,
        "recommendations": [],
        "error": None,
    }

    score = 0
    txt_values: list[str] = []

    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=5)
            values = [answer.to_text() for answer in answers]
            result["records"][record_type] = values
            if values:
                score += RECORD_WEIGHTS.get(record_type, 5)
            if record_type == "TXT":
                txt_values = values
        except Exception:
            result["records"][record_type] = []

    result["score"] = min(score, 100)

    if not result["records"].get("A") and not result["records"].get("AAAA"):
        result["recommendations"].append(
            "No A/AAAA records found — domain may be misconfigured or offline."
        )
    if not result["records"].get("MX"):
        result["recommendations"].append(
            "No MX records — outbound email for this domain may not work."
        )
    if not any("v=spf1" in v.lower() for v in txt_values):
        result["recommendations"].append(
            "No SPF TXT record at apex — add SPF to reduce email spoofing risk."
        )
    if not result["records"].get("CAA"):
        result["recommendations"].append(
            "No CAA records — consider restricting which CAs may issue certificates."
        )

    return result
