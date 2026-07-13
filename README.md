# TESTABLE OWASP Dependency-Check — 100% Java SCA Metrics Validation Repo

Java **Software Composition Analysis (SCA)** metrics validation repository aligned with **Testable Strategy Metrics Mapping v0.2**. **100% Java** — all metric computation, export, validation, and S3 upload run through Maven and Java main classes.

| Component | Language | Entry point |
|-----------|----------|-------------|
| Demo application | Java | `com.testable.demo.App` |
| Metrics engine | Java | `com.testable.metrics.MetricsReporter` |
| Platform export | Java | `com.testable.metrics.PlatformExporter` |
| Gate validation | Java | `com.testable.metrics.ValidateGateMain` |
| S3 upload | Java | `com.testable.metrics.S3PlatformUploader` |
| Unit tests | Java (JUnit 5) | `com.testable.metrics.MetricsGateSchemaTest` |

## Quick validation (offline — no NVD download)

```powershell
cd f:\Testable\java\dependency-check
.\mvnw.cmd test -Poffline-validation
```

Expected: `METRICS GATE VALIDATION: PASS (100/100)`

## Maven commands

| Command | Purpose |
|---------|---------|
| `mvnw test` | Run all JUnit tests |
| `mvnw test -Poffline-validation` | Offline export + 100/100 gate |
| `mvnw exec:java@export-offline` | Export from clean fixture |
| `mvnw exec:java@validate-gate` | Validate platform JSON |
| `mvnw exec:java@export-platform` | Export after live Dependency-Check scan |
| `mvnw exec:java@upload-s3` | Upload to S3 (needs `TESTABLE_METRICS_BUCKET`) |

## Full scan pipeline

```powershell
$env:NVD_API_KEY = "your-nvd-api-key"
.\mvnw.cmd clean test
.\mvnw.cmd versions:display-dependency-updates -DoutputFile=target/dependency-updates.txt
.\mvnw.cmd dependency-check:check -Dformats=JSON,HTML
.\mvnw.cmd exec:java@export-platform
.\mvnw.cmd exec:java@validate-gate
```

## S3 platform path

```text
dependency_check/0/dependency_check.json
```

## Output files

| File | Purpose |
|------|---------|
| `dependency_check/0/dependency_check.json` | TESTABLE platform gate file (S3 key) |
| `target/dependency-check/dependency-check-report.json` | Raw Dependency-Check output |
| `reports/metrics-report.json` | Full detail per metric |

## Metrics covered (8)

All under **White Box → Security White-box Testing → Dependency Risk (SCA)**.

See [docs/TESTING_TEAM_GUIDE.md](docs/TESTING_TEAM_GUIDE.md) and [docs/metrics-mapping.md](docs/metrics-mapping.md).
