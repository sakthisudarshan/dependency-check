"""Schema and validation tests for TESTABLE Dependency-Check platform metrics."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "platform_dependency_check_golden.json"
CLASSIFICATIONS = ROOT / "fixtures" / "classifications.json"
VALIDATOR = ROOT / "scripts" / "validate_metrics_gate.py"
CLEAN_REPORT = ROOT / "tests" / "fixtures" / "dependency-check_clean.json"


def test_golden_fixture_passes_require_100():
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--file", str(FIXTURE), "--require-100"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_golden_fixture_has_eight_classifications():
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    expected = json.loads(CLASSIFICATIONS.read_text(encoding="utf-8"))
    assert len(data["metrics"]) == 8
    assert [metric["classification"] for metric in data["metrics"]] == expected
    assert all(metric["value"] == 100 for metric in data["metrics"])
    assert all(metric["result"] == "PASS" for metric in data["metrics"])


def test_fraction_scores_fail_validation(tmp_path):
    bad = json.loads(FIXTURE.read_text(encoding="utf-8"))
    bad["HiddenRelationshipMapping"] = 0.88
    bad["metrics"][0]["value"] = 0.88
    bad_file = tmp_path / "bad.json"
    bad_file.write_text(json.dumps(bad), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, str(VALIDATOR), "--file", str(bad_file), "--require-100"],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    assert result.returncode == 1


def test_compute_metrics_from_clean_fixture():
    sys.path.insert(0, str(ROOT))
    from scripts.metrics_reporter import compute_metrics

    report = compute_metrics(CLEAN_REPORT)
    assert report.total_components == 3
    assert report.total_vulnerabilities == 0
    assert report.distinct_cves == 0
    assert all(metric.normalised_score == 100 for metric in report.metrics)
    assert all(metric.result == "PASS" for metric in report.metrics)
