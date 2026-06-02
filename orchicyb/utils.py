from urllib.parse import urlparse


def normalize_url(value: str) -> str:
    if not value.startswith(("http://", "https://")):
        return "https://" + value
    return value


def domain_from_url(value: str) -> str:
    parsed = urlparse(normalize_url(value))
    host = parsed.netloc.split(":")[0]
    return host.lower().strip(".")


def risk_level(score: int) -> str:
    if score >= 85:
        return "Low"
    if score >= 65:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"


def risk_level_style(level: str) -> str:
    styles = {
        "Low": "bold green",
        "Moderate": "bold yellow",
        "High": "bold orange1",
        "Critical": "bold red",
    }
    return styles.get(level, "white")


def score_style(score: int) -> str:
    if score >= 85:
        return "green"
    if score >= 65:
        return "yellow"
    if score >= 40:
        return "orange1"
    return "red"
