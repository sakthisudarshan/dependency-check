# OWASP Dependency-Check Metrics Mapping

## Tool coverage

| Metric | Technique | Primary tool (Excel) | Data source |
|--------|-----------|----------------------|-------------|
| Hidden Relationship Mapping | Transitive Dependency Analysis | OWASP Dependency-Check 10.0.4 | `includedBy`, `vulnerabilities` in JSON report |
| Legal Risk Validation | License Compliance Testing | OWASP Dependency-Check 10.0.5 | `license`, package metadata |
| Trust Integrity Verification | Supply Chain Security Analysis | OWASP Dependency-Check 10.0.6 | package confidence, vulnerability density |
| Community Vitality Tracking | Dependency Health Monitoring | OWASP Dependency-Check 10.0.7 | fix availability + version freshness proxy |
| Mitigation Effort Ranking | Risk Prioritization | OWASP Dependency-Check 10.0.8 | CVSS severity weighting + fix coverage |
| Real-Time Alerting | Continuous Dependency Monitoring | OWASP Dependency-Check 10.0.9 | delta vs `baseline/cve_snapshot.json` |
| Known CVE Count | Vulnerability Dependency Detection | OWASP Dependency-Check 10.0.10 | distinct `CVE-*` identifiers |
| Version Lag Assessment | Outdated Dependency Detection | OWASP Dependency-Check 10.0.11 | versions-maven-plugin + report versions |

All eight metrics are **derived** from Dependency-Check output (Excel: *Metrics emitted directly?* = No).

## Per-metric derivation

| # | Classification | Excel derivation | Implementation |
|---|----------------|------------------|----------------|
| 1 | Hidden Relationship Mapping | `count(transitive)/count(components)` | `includedBy` non-empty → transitive; risk = vuln×20 + flagged×5 |
| 2 | Legal Risk Validation | `count(violations)/count(packages)` | copyleft/restricted license pattern match |
| 3 | Trust Integrity Verification | vulnerability density + critical ratio | low-confidence packages + deprecated registry notes |
| 4 | Community Vitality Tracking | `count(current==latest)/count(deps)` | abandoned = vulns without fix metadata; low-activity = outdated |
| 5 | Mitigation Effort Ranking | weighted severity average | prioritization % for Critical/High deps with remediation hints |
| 6 | Real-Time Alerting | alert density | new CVEs since baseline snapshot |
| 7 | Known CVE Count | `count(distinct CVE id)` | severity-weighted CVE score |
| 8 | Version Lag Assessment | `count(current!=latest)/count(deps)` | versions-maven-plugin major-version lag |

## Normalisation (0–100)

Each metric uses the Excel normalisation formula, e.g. `MAX(0, 100 – Risk_Score)`.

Metrics 5 and 6 gate at **100%** coverage/response rate.

## Platform JSON

`dependency_check/0/dependency_check.json` includes:

- `total_components`, `total_vulnerabilities`, `distinct_cves`
- 8 platform score keys (0–100 scale)
- `metrics[]` with `classification`, `value`, `coverage`, `result`

## Supplementary inputs

| File | Purpose |
|------|---------|
| `target/dependency-check/dependency-check-report.json` | Primary scan output |
| `target/dependency-updates.txt` | Version lag probe from versions-maven-plugin |
| `baseline/cve_snapshot.json` | Previous CVE set for Real-Time Alerting delta |
