from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from secpipeline.knowledge import answer_question

app = FastAPI(title="secpipeline metrics", version="0.1.0")
REPORTS_DIR = Path(".reports")


class AskIn(BaseModel):
    question: str = Field(min_length=3)
    top_k: int = Field(default=3, ge=1, le=10)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics/summary")
def metrics_summary():
    report_path = REPORTS_DIR / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="no report.json, run: python -m secpipeline scan")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    return {
        "project": data.get("project"),
        "summary": data.get("summary"),
        "findings_total": len(data.get("findings") or []),
        "scanned_at": (data.get("meta") or {}).get("scanned_at"),
    }


@app.get("/metrics/findings")
def metrics_findings(severity: str | None = None):
    report_path = REPORTS_DIR / "report.json"
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="no report.json")
    data = json.loads(report_path.read_text(encoding="utf-8"))
    findings = data.get("findings") or []
    if severity:
        findings = [f for f in findings if f.get("severity") == severity.lower()]
    return {"items": findings, "count": len(findings)}


@app.post("/ask")
def ask(body: AskIn):
    return answer_question(body.question, top_k=body.top_k)
