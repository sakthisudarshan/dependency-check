$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot\..

Write-Host "==> Offline metric validation (no NVD download)"
python -m pytest -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "==> Compute metrics from clean Dependency-Check fixture"
python -c @"
import json, sys
from pathlib import Path
sys.path.insert(0, '.')
from scripts.metrics_reporter import compute_metrics, build_testable_gate_report, build_platform_dependency_check_json
report = compute_metrics(Path('tests/fixtures/dependency-check_clean.json'))
gate = build_testable_gate_report(report)
platform = build_platform_dependency_check_json(report, gate, report_path='tests/fixtures/dependency-check_clean.json')
out = Path('dependency-check/0/dependency-check.json')
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(platform, indent=2), encoding='utf-8')
print('Wrote', out)
"@

Write-Host "==> Validate 100/100 metrics gate"
python scripts/validate_metrics_gate.py --require-100
exit $LASTEXITCODE
