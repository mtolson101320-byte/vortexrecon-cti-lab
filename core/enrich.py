from typing import Any, Dict
from core.models import EnrichmentResult, ReconResult
from core.utils import IOC_DOMAIN, IOC_IP
from modules.virustotal import vt_enabled, domain_report, ip_report


def _vt_score(vt: Dict[str, Any]) -> int:
    try:
        stats = vt["data"]["attributes"]["last_analysis_stats"]
        mal = int(stats.get("malicious", 0))
        susp = int(stats.get("suspicious", 0))
        score = mal * 20 + susp * 10
        return max(10, min(95, score))
    except Exception:
        return 10


def enrich_recon(recon: ReconResult) -> EnrichmentResult:
    enr = EnrichmentResult(recon=recon)
    vt_data: Dict[str, Any] = {}

    if vt_enabled():
        if recon.input.ioc_type == IOC_DOMAIN:
            vt_data = domain_report(recon.input.value)
        elif recon.input.ioc_type == IOC_IP:
            vt_data = ip_report(recon.input.value)
        enr.enrichment_sources["virustotal"] = {"enabled": True}
    else:
        enr.enrichment_sources["virustotal"] = {"enabled": False}

    enr.reputation = {"engine": "virustotal" if vt_enabled() else "none", "vt": vt_data}

    if vt_data and "error" not in vt_data:
        enr.risk_score = _vt_score(vt_data)
    else:
        enr.risk_score = 20

    return enr
