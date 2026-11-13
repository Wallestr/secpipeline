from __future__ import annotations

import json
from pathlib import Path

from secpipeline.models import SEVERITY_ORDER, ScanReport


def sort_findings(report: ScanReport) -> None:
    report.findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f.severity.lower(), 99), f.scanner, f.rule_id)
    )


def write_json(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def write_markdown(report: ScanReport, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Security report: {report.project}",
        "",
        "## Summary",
    ]
    for sev, count in report.counts_by_severity().items():
        lines.append(f"- {sev}: {count}")
    lines.extend(["", "## Findings", ""])
    if not report.findings:
        lines.append("No findings.")
    for f in report.findings:
        loc = f.file or "-"
        if f.line:
            loc = f"{loc}:{f.line}"
        lines.append(f"### [{f.severity}] {f.title}")
        lines.append(f"- scanner: `{f.scanner}`")
        lines.append(f"- rule: `{f.rule_id}`")
        lines.append(f"- where: `{loc}`")
        if f.evidence:
            lines.append(f"- evidence: `{f.evidence}`")
        if f.remediation:
            lines.append(f"- fix: {f.remediation}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def gate_failed(report: ScanReport, fail_on: str) -> bool:
    threshold = SEVERITY_ORDER.get(fail_on.lower())
    if threshold is None:
        raise ValueError(f"unknown severity: {fail_on}")
    for f in report.findings:
        if SEVERITY_ORDER.get(f.severity.lower(), 99) <= threshold:
            return True
    return False
