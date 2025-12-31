from typing import Any, Dict, List

from core.models import EnrichmentResult, ThreatReport
from core.utils import IOC_DOMAIN, IOC_EMAIL, IOC_IP


class ThreatAIEngine:
    def __init__(self, model_name: str = "rule-based-v1") -> None:
        self.model_name = model_name

    def summarize(self, enrichment: EnrichmentResult) -> ThreatReport:
        ioc = enrichment.recon.input
        mitre_tags: List[str] = []
        priority = "medium"

        if ioc.ioc_type in (IOC_DOMAIN, IOC_IP):
            mitre_tags += ["TA0043: Reconnaissance", "TA0001: Initial Access"]
        if ioc.ioc_type == IOC_EMAIL:
            mitre_tags.append("T1566: Phishing")
            priority = "high"
        if enrichment.risk_score and enrichment.risk_score >= 80:
            priority = "critical"

        summary = "\n".join([
            f"IOC: {ioc.value} ({ioc.ioc_type})",
            f"Risk score: {enrichment.risk_score}",
            f"Reputation engine: {enrichment.reputation.get('engine')}",
            "",
            "Assessment:",
            "- Locally generated assessment (rule-based).",
            "- Wire an LLM here for richer analysis."
        ])

        findings: Dict[str, Any] = {
            "suspicion_reasons": [],
            "recommended_next_steps": []
        }

        if ioc.ioc_type == IOC_EMAIL:
            findings["suspicion_reasons"].append("Email IOCs are common in phishing/BEC.")
            findings["recommended_next_steps"].append("Search mail logs for this address.")
        if ioc.ioc_type in (IOC_DOMAIN, IOC_IP):
            findings["suspicion_reasons"].append("Network IOCs may be C2 / staging infra.")
            findings["recommended_next_steps"].append("Check DNS/proxy/firewall logs for hits.")

        return ThreatReport(
            enrichment=enrichment,
            ai_summary=summary,
            ai_findings=findings,
            mitre_tags=mitre_tags,
            priority=priority
        )
