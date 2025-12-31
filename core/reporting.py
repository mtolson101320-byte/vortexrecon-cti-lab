import os
from core.models import ThreatReport
from core.utils import save_json


def export_json(report: ThreatReport, path: str) -> None:
    save_json(report.to_dict(), path)


def export_markdown(report: ThreatReport, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    t = report

    lines = [
        "# VortexRecon Threat Report",
        "",
        f"**IOC:** `{t.enrichment.recon.input.value}` ({t.enrichment.recon.input.ioc_type})  ",
        f"**Risk Score:** {t.enrichment.risk_score}  ",
        f"**Priority:** {t.priority}  ",
        "",
        "## AI Summary",
        "",
        t.ai_summary,
        "",
        "## MITRE Tags",
        "",
    ]
    lines += [f"- {tag}" for tag in t.mitre_tags]
    lines += [
        "",
        "## AI Findings",
        "",
        "### Suspicion reasons",
    ]
    lines += [f"- {r}" for r in t.ai_findings.get("suspicion_reasons", [])]
    lines += [
        "",
        "### Recommended next steps",
    ]
    lines += [f"- {s}" for s in t.ai_findings.get("recommended_next_steps", [])]
    lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))
