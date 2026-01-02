import argparse
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

from core.recon import run_recon
from core.enrich import enrich_recon
from core.ai_engine import ThreatAIEngine
from core.reporting import export_json, export_markdown
from core.utils import load_yaml, save_json


def get_settings():
    cfg_path = Path(__file__).parent / "config" / "settings.yaml"
    return load_yaml(str(cfg_path))


def cmd_scan(args):
    recon = run_recon(args.value)
    out_dir = Path("output") / "recon"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"recon_{recon.input.ioc_type}_{recon.input.value.replace('/', '_')}.json"
    save_json(recon.to_dict(), str(out_path))
    print(f"[+] Recon complete → {out_path}")


def cmd_enrich(args):
    recon = run_recon(args.value)
    enrichment = enrich_recon(recon)
    out_dir = Path("output") / "enrichment"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"enrich_{recon.input.ioc_type}_{recon.input.value.replace('/', '_')}.json"
    save_json(enrichment.to_dict(), str(out_path))
    print(f"[+] Enrichment complete → {out_path}")


def cmd_ai(args):
    settings = get_settings()
    engine_name = settings.get("ai", {}).get("engine", "rule-based-v1")
    engine = ThreatAIEngine(model_name=engine_name)

    recon = run_recon(args.value)
    enrichment = enrich_recon(recon)
    report = engine.summarize(enrichment)

    reports_dir = Path(settings.get("reporting", {}).get("output_dir", "output/reports"))
    reports_dir.mkdir(parents=True, exist_ok=True)

    base_name = f"report_{recon.input.ioc_type}_{recon.input.value.replace('/', '_')}"
    json_path = reports_dir / f"{base_name}.json"
    md_path = reports_dir / f"{base_name}.md"

    export_json(report, str(json_path))
    export_markdown(report, str(md_path))

    print(f"[+] AI threat report generated:")
    print(f"    JSON → {json_path}")
    print(f"    MD   → {md_path}")


def build_parser():
    p = argparse.ArgumentParser(prog="vortexrecon", description="VortexRecon AI/CTI Recon Toolkit")
    sub = p.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Run basic recon on an IOC")
    scan.add_argument("--value", required=True, help="IOC value (domain, IP, email, hash)")
    scan.set_defaults(func=cmd_scan)

    enr = sub.add_parser("enrich", help="Run recon + enrichment pipeline")
    enr.add_argument("--value", required=True, help="IOC value (domain, IP, email, hash)")
    enr.set_defaults(func=cmd_enrich)

    ai = sub.add_parser("ai", help="Run full AI-driven threat report pipeline")
    ai.add_argument("--value", required=True, help="IOC value (domain, IP, email, hash)")
    ai.set_defaults(func=cmd_ai)

    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
