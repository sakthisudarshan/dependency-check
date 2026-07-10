#!/usr/bin/env python3
"""Post-process OWASP Dependency-Check output for the TESTABLE platform.

Run after `mvnw clean test dependency-check:check` in CI or locally.
Writes dependency-check/0/dependency-check.json with all 8 SCA metrics.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.metrics_reporter import (  # noqa: E402
    build_platform_dependency_check_json,
    build_testable_gate_report,
    compute_metrics,
    render_markdown,
)


def _find_report() -> Path | None:
    candidates = [
        ROOT / "target" / "dependency-check" / "dependency-check-report.json",
        ROOT / "target" / "dependency-check-report.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def main() -> int:
    fail_on_gate = "--fail-on-gate" in sys.argv
    report_path = _find_report()
    version_updates_path = ROOT / "target" / "dependency-updates.txt"
    baseline_path = ROOT / "baseline" / "cve_snapshot.json"
    out_dir = ROOT / "dependency-check" / "0"
    platform_file = out_dir / "dependency-check.json"
    out_dir.mkdir(parents=True, exist_ok=True)

    if report_path is None:
        print("Missing Dependency-Check JSON report under target/", file=sys.stderr)
        print("Run: .\\mvnw.cmd clean test dependency-check:check", file=sys.stderr)
        return 2

    report = compute_metrics(
        report_path,
        version_updates_path=version_updates_path if version_updates_path.exists() else None,
        baseline_path=baseline_path if baseline_path.exists() else None,
    )
    gate_report = build_testable_gate_report(report)
    platform_report = build_platform_dependency_check_json(
        report,
        gate_report,
        report_path=str(report_path.relative_to(ROOT)).replace("\\", "/"),
    )

    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "sca-gate.json").write_text(
        json.dumps(gate_report, indent=2),
        encoding="utf-8",
    )
    (reports_dir / "metrics-report.json").write_text(
        json.dumps(
            {
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "tool": report.tool,
                "totalComponents": report.total_components,
                "totalVulnerabilities": report.total_vulnerabilities,
                "distinctCves": report.distinct_cves,
                "overallScore": min(m.normalised_score for m in report.metrics),
                "metrics": [metric.__dict__ for metric in report.metrics],
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    (reports_dir / "metrics-report.md").write_text(render_markdown(report), encoding="utf-8")
    platform_file.write_text(json.dumps(platform_report, indent=2), encoding="utf-8")

    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    cves = sorted(
        {
            str(vuln.get("name", "")).upper()
            for dep in report.dependencies
            for vuln in dep.get("vulnerabilities") or []
            if str(vuln.get("name", "")).startswith("CVE-")
        }
    )
    baseline_path.write_text(
        json.dumps({"cves": cves, "updatedAt": datetime.now(timezone.utc).isoformat()}, indent=2),
        encoding="utf-8",
    )

    print(f"Wrote platform gate: {platform_file}")
    print(f"Wrote detailed report: {reports_dir / 'metrics-report.json'}")
    print(f"Updated baseline CVE snapshot: {baseline_path}")

    if fail_on_gate and not gate_report["all_gates_passed"]:
        print("SCA gate FAILED", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
