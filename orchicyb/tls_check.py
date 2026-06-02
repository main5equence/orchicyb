import socket
import ssl
from datetime import datetime, timezone


def check_tls(domain: str, port: int = 443, timeout: float = 8) -> dict:
    result = {
        "domain": domain,
        "port": port,
        "reachable": False,
        "issuer": None,
        "subject": None,
        "expires": None,
        "days_remaining": None,
        "protocol": None,
        "score": 0,
        "recommendations": [],
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure:
                cert = secure.getpeercert()
                result["reachable"] = True
                result["protocol"] = secure.version()
                result["issuer"] = _format_name(cert.get("issuer"))
                result["subject"] = _format_name(cert.get("subject"))

                not_after = cert.get("notAfter")
                if not_after:
                    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )
                    result["expires"] = expires.isoformat()
                    days = (expires - datetime.now(timezone.utc)).days
                    result["days_remaining"] = days

                    if days < 0:
                        result["score"] = 0
                        result["recommendations"].append(
                            "Certificate has expired — renew immediately."
                        )
                    elif days < 14:
                        result["score"] = 40
                        result["recommendations"].append(
                            f"Certificate expires in {days} days — schedule renewal."
                        )
                    elif days < 30:
                        result["score"] = 70
                        result["recommendations"].append(
                            f"Certificate expires in {days} days — plan renewal soon."
                        )
                    else:
                        result["score"] = 100
                else:
                    result["score"] = 60
                    result["recommendations"].append(
                        "Could not read certificate expiry — verify manually."
                    )

                if result["protocol"] and "TLSv1.2" not in result["protocol"] and "TLSv1.3" not in result["protocol"]:
                    result["score"] = min(result["score"], 50)
                    result["recommendations"].append(
                        f"Negotiated protocol is {result['protocol']} — prefer TLS 1.2+."
                    )

    except (socket.timeout, socket.gaierror, ssl.SSLError, OSError) as exc:
        result["error"] = str(exc)
        result["recommendations"].append(
            "TLS endpoint unreachable — confirm HTTPS is enabled and port 443 is open."
        )

    return result


def _format_name(name_tuple) -> str | None:
    if not name_tuple:
        return None
    parts = []
    for rdn in name_tuple:
        for key, value in rdn:
            label = key[0] if isinstance(key, tuple) else str(key)
            parts.append(f"{label}={value}")
    return ", ".join(parts)
