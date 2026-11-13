from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    scanner: str
    rule_id: str
    title: str
    severity: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    project: str
    findings: list[Finding] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def counts_by_severity(self) -> dict[str, int]:
        out = {k: 0 for k in SEVERITY_ORDER}
        for f in self.findings:
            key = f.severity.lower()
            if key in out:
                out[key] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "project": self.project,
            "meta": self.meta,
            "summary": self.counts_by_severity(),
            "findings": [f.to_dict() for f in self.findings],
        }
