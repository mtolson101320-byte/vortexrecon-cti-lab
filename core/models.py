from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from core.utils import detect_ioc_type, utc_now_iso


@dataclass
class ReconInput:
    value: str
    ioc_type: str

    @classmethod
    def from_value(cls, value: str) -> "ReconInput":
        return cls(value=value, ioc_type=detect_ioc_type(value))


@dataclass
class ReconResult:
    input: ReconInput
    basic_info: Dict[str, Any] = field(default_factory=dict)
    osint_sources: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EnrichmentResult:
    recon: ReconResult
    reputation: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    risk_score: Optional[int] = None
    enrichment_sources: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ThreatReport:
    enrichment: EnrichmentResult
    ai_summary: str
    ai_findings: Dict[str, Any] = field(default_factory=dict)
    mitre_tags: List[str] = field(default_factory=list)
    priority: str = "medium"
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
