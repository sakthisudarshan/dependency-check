# TESTABLE OWASP Dependency-Check — Java SCA Metrics Validation Repo

Java **Software Composition Analysis (SCA)** metrics validation repository aligned with **Testable Strategy Metrics Mapping v0.2**. Uses **OWASP Dependency-Check** as the primary tool for all 8 **Dependency Risk (SCA)** metrics mapped to Java.

| Tool | Metrics | Data source |
|------|---------|-------------|
| **OWASP Dependency-Check** | 8 SCA | `target/dependency-check/dependency-check-report.json` |
| **versions-maven-plugin** (supplementary) | Version Lag Assessment | `target/dependency-updates.txt` |

**Maintained at 100/100** on all eight classifications when the demo project has zero known CVEs, permissive licenses, and current dependency versions.

## Quick validation (offline — no NVD download)

```powershell
cd f:\Testable\java\dependency-check
.\scripts\run_offline_validation.ps1
```

Expected: `METRICS GATE VALIDATION: PASS (100/100)`

## Full scan validation (requires NVD data download)

```powershell
cd f:\Testable\java\dependency-check
.\scripts\run_dependency_check.ps1
```

> **Note:** The first Dependency-Check run downloads NVD data (can take 10+ minutes). Set `NVD_API_KEY` to avoid rate limits. Subsequent runs are faster.

## Metrics covered (8)

All under **White Box → Security White-box Testing → Dependency Risk (SCA)**:

| Classification | Technique | Metric |
|----------------|-----------|--------|
| Transitive Dependency Analysis | Hidden Relationship Mapping | Hidden Relationship Mapping |
| License Compliance Testing | Legal Risk Validation | Legal Risk Validation |
| Supply Chain Security Analysis | Trust Integrity Verification | Trust Integrity Verification |
| Dependency Health Monitoring | Community Vitality Tracking | Community Vitality Tracking |
| Risk Prioritization | Mitigation Effort Ranking | Mitigation Effort Ranking |
| Continuous Dependency Monitoring | Real-Time Alerting | Real-Time Alerting |
| Vulnerability Dependency Detection | Known CVE Count | Known CVE Count |
| Outdated Dependency Detection | Version Lag Assessment | Version Lag Assessment |

## Pipeline

```powershell
.\mvnw.cmd clean test
.\mvnw.cmd versions:display-dependency-updates -DoutputFile=target/dependency-updates.txt
.\mvnw.cmd dependency-check:check -Dformats=JSON,HTML
python scripts/export_testable_dependency_check.py
python scripts/validate_metrics_gate.py --require-100

# Optional S3 upload (required for TESTABLE platform trigger)
$env:TESTABLE_METRICS_BUCKET = "your-bucket"
.\scripts\upload_platform_to_s3.ps1
```

## Output files

| File | Purpose |
|------|---------|
| `dependency_check/0/dependency_check.json` | TESTABLE platform gate file (S3 key) |
| `target/dependency-check/dependency-check-report.json` | Raw Dependency-Check output |
| `reports/metrics-report.json` | Full detail per metric + derivations |
| `baseline/cve_snapshot.json` | CVE baseline for Real-Time Alerting delta |

## Verify metrics without a full scan

Use the clean fixture to validate metric logic offline:

```powershell
python -m pytest -q
```

## Mapping reference

See [docs/TESTING_TEAM_GUIDE.md](docs/TESTING_TEAM_GUIDE.md) for S3 path and platform integration details.
