# Testing Team Guide — Dependency-Check SCA Gate (100/100)

This repository is the **reference implementation** for TESTABLE **Dependency Risk (SCA)** metrics using **OWASP Dependency-Check** on Java. Your team should use this guide to verify all eight SCA classifications report **100/100 PASS**.

## Repository

| Item | Value |
|------|-------|
| GitHub | https://github.com/sakthisudarshan/dependency-check |
| Branch | `main` |
| Tool | OWASP Dependency-Check (`dependency_check`) |

## S3 platform path (required for trigger)

TESTABLE reads metrics from this exact S3 key:

```text
dependency_check/0/dependency_check.json
```

The repo writes the same relative path locally before upload:

```text
dependency_check/0/dependency_check.json
```

If this folder/key is missing in S3, the **Dependency_check** tool will not appear in the bucket listing and all eight SCA metrics will show **1/100 FAIL**.

## Metrics to verify (8 classifications)

| # | Classification | Expected score |
|---|----------------|----------------|
| 1 | Hidden Relationship Mapping | 100/100 |
| 2 | Legal Risk Validation | 100/100 |
| 3 | Trust Integrity Verification | 100/100 |
| 4 | Community Vitality Tracking | 100/100 |
| 5 | Mitigation Effort Ranking | 100/100 |
| 6 | Real-Time Alerting | 100/100 |
| 7 | Known CVE Count | 100/100 |
| 8 | Version Lag Assessment | 100/100 |

## One-command validation (offline — no NVD download)

```powershell
git clone https://github.com/sakthisudarshan/dependency-check.git
cd dependency-check
.\scripts\run_offline_validation.ps1
```

**Expected final line:** `METRICS GATE VALIDATION: PASS (100/100)`

## Full scan + S3 upload

```powershell
$env:NVD_API_KEY = "your-nvd-api-key"
$env:TESTABLE_METRICS_BUCKET = "your-testable-metrics-bucket"
.\scripts\run_dependency_check.ps1
```

Or upload manually after export:

```powershell
python scripts/export_testable_dependency_check.py
.\scripts\upload_platform_to_s3.ps1
```

## Files your review must check

| File | Purpose |
|------|---------|
| `dependency_check/0/dependency_check.json` | **Primary file** read by TESTABLE taxonomy gate / S3 |
| `reports/sca-gate.json` | Dashboard-format summary |
| `reports/metrics-report.json` | Full metrics detail |

### Required content in `dependency_check/0/dependency_check.json`

```json
{
  "exit": 0,
  "scan_ok": true,
  "tool": "dependency_check",
  "platform_file": "dependency_check/0/dependency_check.json",
  "overall_score": 100,
  "HiddenRelationshipMapping": 100,
  "metrics": [
    {
      "classification": "Known CVE Count",
      "value": 100,
      "result": "PASS",
      "coverage": 100
    }
  ]
}
```

**Critical:** Scores must be **0–100 integers**, not fractions like `0.88` (which displays as **1/100 FAIL** on the gate).

## TESTABLE platform integration

After Dependency-Check analysis completes, the export step **must** run:

```powershell
python scripts/export_testable_dependency_check.py
```

If the platform runs Dependency-Check alone without export, all eight SCA metrics will show **1/100 FAIL** even when dependencies are clean.

## Validation checklist

- [ ] `.\scripts\run_offline_validation.ps1` reports **PASS (100/100)**
- [ ] `dependency_check/0/dependency_check.json` exists with `"tool": "dependency_check"`
- [ ] S3 contains `dependency_check/0/dependency_check.json`
- [ ] All 8 `metrics[].result` fields equal `"PASS"`
- [ ] `distinct_cves` equals **0** on the clean demo project
- [ ] GitHub Actions workflow **Dependency-Check SCA Validation** is green on `main`

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Tool missing from S3 bucket listing | Wrong folder name (`dependency-check/` vs `dependency_check/`) | Use `dependency_check/0/dependency_check.json` |
| Gate shows **1/100** on all metrics | Export step skipped | Run `python scripts/export_testable_dependency_check.py` |
| `platform file not found` | Export step skipped | Run offline or full validation script |
| First scan hangs | NVD database download | Set `NVD_API_KEY`; allow 10–30 min on first run |

## Do not change without re-validating

- `scripts/export_testable_dependency_check.py` — platform JSON format and S3 path
- `scripts/metrics_reporter.py` — metric formulas and 0–100 scale
- `dependency_check/0/dependency_check.json` — TESTABLE platform file
