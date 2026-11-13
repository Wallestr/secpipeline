from __future__ import annotations

import re
from pathlib import Path

import httpx

from secpipeline.models import Finding

REQ_LINE = re.compile(
    r"""^\s*([A-Za-z0-9_.-]+)\s*(?:==|===|>=|<=|~=|!=|>|<)\s*([0-9][^;\s#]*)""",
)


def parse_requirements(path: Path) -> list[tuple[str, str]]:
    packages: list[tuple[str, str]] = []
    if not path.exists():
        return packages
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        m = REQ_LINE.match(line)
        if m:
            packages.append((m.group(1).lower(), m.group(2)))
    return packages


def _query_osv(name: str, version: str) -> list[dict]:
    payload = {
        "package": {"name": name, "ecosystem": "PyPI"},
        "version": version,
    }
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.post("https://api.osv.dev/v1/query", json=payload)
            if resp.status_code >= 400:
                return []
            data = resp.json()
            return data.get("vulns") or []
    except httpx.HTTPError:
        return []


def _severity_from_osv(vuln: dict) -> str:
    # osv иногда кладёт severity по-разному, берём что есть
    for item in vuln.get("severity") or []:
        score = str(item.get("score", "")).upper()
        if "CRITICAL" in score:
            return "critical"
        if "HIGH" in score:
            return "high"
        if "MEDIUM" in score:
            return "medium"
        if "LOW" in score:
            return "low"
    db = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db, str):
        return db.lower()
    return "medium"


def scan(root: Path, requirements_file: str = "requirements.txt") -> list[Finding]:
    req_path = root / requirements_file
    findings: list[Finding] = []
    for name, version in parse_requirements(req_path):
        for vuln in _query_osv(name, version):
            vuln_id = vuln.get("id") or "OSV-UNKNOWN"
            summary = (vuln.get("summary") or vuln.get("details") or "Known vulnerability").split("\n")[0]
            findings.append(
                Finding(
                    scanner="deps",
                    rule_id=vuln_id,
                    title=f"{name}=={version}: {summary[:120]}",
                    severity=_severity_from_osv(vuln),
                    file=requirements_file,
                    remediation=f"Обнови пакет {name} до версии без уязвимости ({vuln_id}).",
                )
            )
    return findings
