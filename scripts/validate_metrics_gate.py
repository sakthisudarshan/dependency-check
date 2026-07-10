#!/usr/bin/env python3
"""Validate TESTABLE Dependency-Check gate output for the testing team.

Checks dependency-check/0/dependency-check.json for:
  - All 8 required SCA classifications present
  - Each metric PASS against Excel gate thresholds (default)
  - Literal 100/100 on every score when --require-100
  - Zero vulnerabilities when --require-100

Usage:
  python scripts/validate_metrics_gate.py
  python scripts/validate_metrics_gate.py --require-100
  python scripts/validate_metrics_gate.py --file dependency-check/0/dependency-check.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.metrics_reporter import CLASSIFICATIONS, PLATFORM_SCORE_KEYS  # noqa: E402


def validate_platform_json(
    data: dict,
    *,
    require_perfect: bool,
) -> list[str]:
    errors: list[str] = []

    if data.get("exit") != 0:
        errors.append(f"exit must be 0, got {data.get('exit')!r}")
    if data.get("scan_ok") is not True:
        errors.append("scan_ok must be true")

    total_vulns = data.get("total_vulnerabilities")
    distinct_cves = data.get("distinct_cves")
    if require_perfect and total_vulns != 0:
        errors.append(
            f"total_vulnerabilities must be 0 for 100/100 demo, got {total_vulns!r}"
        )
    if require_perfect and distinct_cves != 0:
        errors.append(f"distinct_cves must be 0 for 100/100 demo, got {distinct_cves!r}")

    for key in PLATFORM_SCORE_KEYS:
        if key not in data:
            errors.append(f"missing platform score key: {key}")
            continue
        value = data[key]
        if not isinstance(value, (int, float)):
            errors.append(f"{key} must be numeric, got {type(value).__name__}")
            continue
        if value <= 1.0:
            errors.append(
                f"{key}={value} looks like a 0-1 fraction; TESTABLE expects 0-100 scale"
            )
        if require_perfect and value < 100:
            errors.append(f"{key}={value} below required minimum 100")

    metrics = data.get("metrics")
    if not isinstance(metrics, list):
        errors.append("metrics array missing from platform JSON")
        return errors

    by_name = {m.get("classification"): m for m in metrics if isinstance(m, dict)}
    for name in CLASSIFICATIONS:
        if name not in by_name:
            errors.append(f"missing classification in metrics[]: {name}")
            continue
        metric = by_name[name]
        value = metric.get("value")
        coverage = metric.get("coverage")
        result = metric.get("result")
        if result != "PASS":
            errors.append(f"{name}: result must be PASS, got {result!r}")
        if require_perfect:
            if not isinstance(value, (int, float)) or value < 100:
                errors.append(f"{name}: value={value!r} below 100")
            if not isinstance(coverage, (int, float)) or coverage < 100:
                errors.append(f"{name}: coverage={coverage!r} below 100")
        else:
            if not isinstance(value, (int, float)):
                errors.append(f"{name}: value={value!r} must be numeric")
            if not isinstance(coverage, (int, float)):
                errors.append(f"{name}: coverage={coverage!r} must be numeric")

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--file",
        default="dependency_check/0/dependency_check.json",
        help="Path to TESTABLE platform dependency_check.json",
    )
    parser.add_argument(
        "--require-100",
        action="store_true",
        help="Require every metric at literal 100/100",
    )
    args = parser.parse_args()

    path = Path(args.file)
    if not path.is_absolute():
        path = ROOT / path

    if not path.exists():
        print(f"FAIL: platform file not found: {path}", file=sys.stderr)
        print("Run: python scripts/export_testable_dependency_check.py", file=sys.stderr)
        return 2

    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_platform_json(data, require_perfect=args.require_100)

    if errors:
        print("METRICS GATE VALIDATION: FAIL")
        for err in errors:
            print(f"  - {err}")
        return 1

    mode = "100/100" if args.require_100 else "Excel gate thresholds"
    print(f"METRICS GATE VALIDATION: PASS ({mode})")
    print(f"  File: {path}")
    print(f"  Components: {data.get('total_components', 0)}")
    print(f"  Vulnerabilities: {data.get('total_vulnerabilities', 0)}")
    print(f"  Distinct CVEs: {data.get('distinct_cves', 0)}")
    print(f"  Classifications: {len(CLASSIFICATIONS)}/8 PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
