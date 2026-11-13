from secpipeline.models import Finding, ScanReport
from secpipeline.report import gate_failed


def test_gate_high():
    report = ScanReport(
        project="demo",
        findings=[
            Finding("secrets", "x", "t", "medium"),
            Finding("secrets", "y", "t", "high"),
        ],
    )
    assert gate_failed(report, "high") is True
    assert gate_failed(report, "critical") is False
