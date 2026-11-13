from pathlib import Path

from secpipeline.scanners import secrets


def test_finds_api_key(tmp_path: Path):
    sample = tmp_path / "cfg.py"
    sample.write_text('api_key = "super_secret_demo_token_12345"\n', encoding="utf-8")
    findings = secrets.scan(tmp_path)
    assert any(f.rule_id == "generic-api-key" for f in findings)


def test_skips_venv(tmp_path: Path):
    bad = tmp_path / ".venv" / "lib" / "x.py"
    bad.parent.mkdir(parents=True)
    bad.write_text('api_key = "super_secret_demo_token_12345"\n', encoding="utf-8")
    assert secrets.scan(tmp_path) == []
