# Testing Team Guide — Dependency-Check SCA Gate (100% Java)

This repository is the **reference implementation** for TESTABLE **Dependency Risk (SCA)** metrics using **OWASP Dependency-Check** on Java. **All pipeline code is Java** — no Python or PowerShell scripts.

## Repository

| Item | Value |
|------|-------|
| GitHub | https://github.com/sakthisudarshan/dependency-check |
| Branch | `main` |
| Tool | OWASP Dependency-Check (`dependency_check`) |
| Language | **Java 17 only** |

## S3 platform path (required for trigger)

```text
dependency_check/0/dependency_check.json
```

## One-command validation (offline)

```powershell
git clone https://github.com/sakthisudarshan/dependency-check.git
cd dependency-check
.\mvnw.cmd test -Poffline-validation
```

**Expected final line:** `METRICS GATE VALIDATION: PASS (100/100)`

## Java entry points

| Class | Maven goal | Purpose |
|-------|------------|---------|
| `OfflineExportMain` | `mvn exec:java@export-offline` | Export from test fixture |
| `PlatformExporter` | `mvn exec:java@export-platform` | Export after live scan |
| `ValidateGateMain` | `mvn exec:java@validate-gate` | Validate 100/100 gate |
| `S3PlatformUploader` | `mvn exec:java@upload-s3` | Upload to S3 |

## S3 upload

```powershell
$env:TESTABLE_METRICS_BUCKET = "your-bucket"
$env:AWS_ACCESS_KEY_ID = "..."
$env:AWS_SECRET_ACCESS_KEY = "..."
$env:AWS_DEFAULT_REGION = "us-east-1"
.\mvnw.cmd exec:java@upload-s3
```

## Validation checklist

- [ ] `mvnw test -Poffline-validation` exits with code 0
- [ ] `dependency_check/0/dependency_check.json` exists with `"tool": "dependency_check"`
- [ ] S3 contains `dependency_check/0/dependency_check.json`
- [ ] All 8 `metrics[].result` fields equal `"PASS"`
- [ ] GitHub Actions workflow is green on `main`
