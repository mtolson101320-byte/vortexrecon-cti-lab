import os
import requests
from typing import Any, Dict

VT_BASE = "https://www.virustotal.com/api/v3"


def vt_enabled() -> bool:
    return bool(os.getenv("VT_API_KEY", "").strip())


def _headers() -> Dict[str, str]:
    key = os.getenv("VT_API_KEY", "").strip()
    return {"x-apikey": key} if key else {}


def _get(path: str) -> Dict[str, Any]:
    url = f"{VT_BASE}{path}"
    resp = requests.get(url, headers=_headers(), timeout=20)

    if resp.status_code == 401:
        return {"error": "VT auth failed (check VT_API_KEY)", "status": 401}
    if resp.status_code >= 400:
        return {"error": f"VT HTTP {resp.status_code}", "status": resp.status_code, "body": resp.text[:200]}

    return resp.json()


def domain_report(domain: str) -> Dict[str, Any]:
    return _get(f"/domains/{domain}")


def ip_report(ip: str) -> Dict[str, Any]:
    return _get(f"/ip_addresses/{ip}")
