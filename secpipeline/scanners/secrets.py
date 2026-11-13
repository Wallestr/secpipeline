from __future__ import annotations

import re
from pathlib import Path

from secpipeline.models import Finding

# простые паттерны, без внешнего движка — для демо и локальных прогонов
PATTERNS = [
    (
        "aws-access-key",
        "high",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        "Похоже на AWS Access Key. Убери из кода, вынеси в secrets.",
    ),
    (
        "generic-api-key",
        "medium",
        re.compile(r"""(?i)(api[_-]?key|token|secret)\s*[:=]\s*['\"][^'\"]{12,}['\"]"""),
        "Жёстко прошитый секрет. Перенеси в env / vault.",
    ),
    (
        "private-key-block",
        "critical",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "Приватный ключ в репозитории. Ротируй и удали из истории.",
    ),
]

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".reports"}
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".env",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".ps1",
    ".md",
    ".txt",
}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {".env", "Dockerfile"}:
            continue
        yield path


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for rule_id, severity, pattern, fix in PATTERNS:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    Finding(
                        scanner="secrets",
                        rule_id=rule_id,
                        title=f"Possible secret: {rule_id}",
                        severity=severity,
                        file=str(path.relative_to(root)).replace("\\", "/"),
                        line=line,
                        evidence=match.group(0)[:80],
                        remediation=fix,
                    )
                )
    return findings
