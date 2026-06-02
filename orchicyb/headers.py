import requests

from .utils import normalize_url, domain_from_url

SECURITY_HEADERS = {
    "Strict-Transport-Security": 20,
    "Content-Security-Policy": 25,
    "X-Frame-Options": 15,
    "X-Content-Type-Options": 10,
    "Referrer-Policy": 10,
    "Permissions-Policy": 10,
    "Cross-Origin-Opener-Policy": 5,
    "Cross-Origin-Resource-Policy": 5,
}

HEADER_HINTS = {
    "Strict-Transport-Security": "Enforce HTTPS for browsers (include max-age and preload where appropriate).",
    "Content-Security-Policy": "Mitigate XSS by restricting script and resource origins.",
    "X-Frame-Options": "Reduce clickjacking risk (DENY or SAMEORIGIN).",
    "X-Content-Type-Options": "Set to nosniff to prevent MIME-type sniffing.",
    "Referrer-Policy": "Limit referrer leakage on cross-origin navigation.",
    "Permissions-Policy": "Disable unused browser features (camera, geolocation, etc.).",
    "Cross-Origin-Opener-Policy": "Isolate browsing context for cross-origin documents.",
    "Cross-Origin-Resource-Policy": "Control which origins may load your resources.",
}


def check_headers(target: str) -> dict:
    url = normalize_url(target)
    domain = domain_from_url(target)
    result = {
        "target": url,
        "domain": domain,
        "reachable": False,
        "status_code": None,
        "final_url": None,
        "https_redirect": None,
        "present": {},
        "missing": [],
        "score": 0,
        "recommendations": [],
        "error": None,
    }

    result["https_redirect"] = _check_https_redirect(domain)

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "orchicyb/0.2 (+https://github.com)"},
        )
        result["reachable"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        headers = response.headers

        score = 0
        for header, points in SECURITY_HEADERS.items():
            if header in headers:
                result["present"][header] = headers.get(header)
                score += points
            else:
                result["missing"].append(header)
                result["recommendations"].append(HEADER_HINTS[header])

        if result["https_redirect"] is False:
            score = max(0, score - 15)
            result["recommendations"].insert(
                0,
                "HTTP does not redirect to HTTPS — enforce TLS for all visitors.",
            )
        elif result["https_redirect"] is True and "Strict-Transport-Security" not in result["present"]:
            result["recommendations"].append(
                "HTTPS redirect works, but HSTS is missing — add Strict-Transport-Security."
            )

        if response.status_code and response.status_code >= 400:
            result["recommendations"].append(
                f"Server returned HTTP {response.status_code} — verify the target URL."
            )

        result["score"] = min(score, 100)
    except requests.RequestException as exc:
        result["error"] = str(exc)
        result["recommendations"].append(
            "Could not reach the target — check DNS, firewall rules, and URL spelling."
        )

    return result


def _check_https_redirect(domain: str) -> bool | None:
    try:
        response = requests.get(
            f"http://{domain}",
            timeout=8,
            allow_redirects=True,
            headers={"User-Agent": "orchicyb/0.2 (+https://github.com)"},
        )
        return response.url.lower().startswith("https://")
    except requests.RequestException:
        return None
