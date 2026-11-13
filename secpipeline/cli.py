from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from secpipeline import __version__
from secpipeline.knowledge import answer_question
from secpipeline.models import ScanReport
from secpipeline.report import gate_failed, sort_findings, write_json, write_markdown
from secpipeline.scanners import deps, secrets


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="secpipeline",
        description="Local security checks for repos + simple reports for CI",
    )
    p.add_argument("--version", action="version", version=f"secpipeline {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Run secret + dependency checks")
    scan.add_argument("path", nargs="?", default=".", help="Project root")
    scan.add_argument("--out", default=".reports", help="Output directory")
    scan.add_argument("--fail-on", default="high", help="Gate threshold: critical|high|medium|low")
    scan.add_argument("--skip-deps", action="store_true", help="Do not call OSV")
    scan.add_argument("--req", default="requirements.txt", help="Requirements file for deps scan")

    ask = sub.add_parser("ask", help="Ask a question over local security notes (tiny RAG)")
    ask.add_argument("question", help="Your question")
    ask.add_argument("--top-k", type=int, default=3)

    sub.add_parser("serve", help="Start metrics API (FastAPI)")

    return p


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).resolve()
    report = ScanReport(
        project=root.name,
        meta={
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "root": str(root),
            "version": __version__,
        },
    )
    report.findings.extend(secrets.scan(root))
    if not args.skip_deps:
        report.findings.extend(deps.scan(root, requirements_file=args.req))
    sort_findings(report)

    out = Path(args.out)
    write_json(report, out / "report.json")
    write_markdown(report, out / "report.md")

    summary = report.counts_by_severity()
    print(json.dumps({"project": report.project, "summary": summary}, ensure_ascii=False))
    print(f"wrote {out / 'report.json'}")
    print(f"wrote {out / 'report.md'}")

    if gate_failed(report, args.fail_on):
        print(f"gate failed: found issues at/above {args.fail_on}", file=sys.stderr)
        return 1
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    result = answer_question(args.question, top_k=args.top_k)
    print(result["answer"])
    if result["sources"]:
        print("\nsources:")
        for src in result["sources"]:
            print(f"- {src}")
    return 0


def cmd_serve(_: argparse.Namespace) -> int:
    import uvicorn

    from secpipeline.api import app

    uvicorn.run(app, host="127.0.0.1", port=8088)
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "scan":
        raise SystemExit(cmd_scan(args))
    if args.cmd == "ask":
        raise SystemExit(cmd_ask(args))
    if args.cmd == "serve":
        raise SystemExit(cmd_serve(args))
    parser.error(f"unknown command: {args.cmd}")


if __name__ == "__main__":
    main()
