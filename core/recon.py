import socket
from typing import Any, Dict

from core.models import ReconInput, ReconResult
from core.utils import IOC_DOMAIN, IOC_IP


def _basic_dns_lookup(domain: str) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    try:
        name, aliases, addrs = socket.gethostbyname_ex(domain)
        data["hostname"] = name
        data["aliases"] = aliases
        data["addresses"] = addrs
    except Exception as e:
        data["error"] = str(e)
    return data


def _basic_ip_info(ip: str) -> Dict[str, Any]:
    return {"ip": ip, "note": "Basic placeholder. Add GeoIP/reputation later."}


def run_recon(value: str) -> ReconResult:
    recon_input = ReconInput.from_value(value)
    result = ReconResult(input=recon_input)

    if recon_input.ioc_type == IOC_DOMAIN:
        result.basic_info["dns"] = _basic_dns_lookup(recon_input.value)
    elif recon_input.ioc_type == IOC_IP:
        result.basic_info["ip_info"] = _basic_ip_info(recon_input.value)
    else:
        result.errors.append(f"IOC type '{recon_input.ioc_type}' not supported for deep recon yet.")

    result.osint_sources["note"] = "Integrate Harpoon/IntelOwl/Shodan/Censys via modules/."
    return result
