from core.models import EnrichmentResult, ReconResult
from core.utils import IOC_DOMAIN, IOC_IP, IOC_EMAIL, IOC_HASH


def _score_from_basic(recon: ReconResult) -> int:
    score = 10
    t = recon.input.ioc_type

    if t == IOC_DOMAIN:
        score += 5
    if t == IOC_IP:
        score += 10
    if t == IOC_EMAIL:
        score += 15
    if t == IOC_HASH:
        score += 20
    if recon.errors:
        score += 5

    return min(score, 95)


def enrich_recon(recon: ReconResult) -> EnrichmentResult:
    enrichment = EnrichmentResult(recon=recon)
    enrichment.tags.append(recon.input.ioc_type)

    enrichment.reputation = {
        "engine": "local-placeholder",
        "classification": "unknown",
        "details": "Wire IntelOwl/VirusTotal/AbuseIPDB here."
    }

    enrichment.risk_score = _score_from_basic(recon)
    enrichment.enrichment_sources["intelowl"] = {"enabled": False}
    return enrichment
