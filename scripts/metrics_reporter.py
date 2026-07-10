#!/usr/bin/env python3
"""Compute TESTABLE Strategy SCA metrics from OWASP Dependency-Check reports.

Metrics mapping source: Testable_Strategy_Metrics_Mapping_v0.2 (White Box)
Primary tool: OWASP Dependency-Check (Java)
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

GATE_NAME = "OWASP Dependency-Check SCA Gate"
TOOL = "dependency-check"

CLASSIFICATIONS: tuple[str, ...] = (
    "Hidden Relationship Mapping",
    "Legal Risk Validation",
    "Trust Integrity Verification",
    "Community Vitality Tracking",
    "Mitigation Effort Ranking",
    "Real-Time Alerting",
    "Known CVE Count",
    "Version Lag Assessment",
)

PLATFORM_SCORE_KEYS: tuple[str, ...] = (
    "HiddenRelationshipMapping",
    "LegalRiskValidation",
    "TrustIntegrityVerification",
    "CommunityVitalityTracking",
    "MitigationEffortRanking",
    "RealTimeAlerting",
    "KnownCVECount",
    "VersionLagAssessment",
)

CLASSIFICATION_TO_PLATFORM_KEY = dict(zip(CLASSIFICATIONS, PLATFORM_SCORE_KEYS))

COPYLEFT_PATTERNS = re.compile(
    r"\b(GPL|AGPL|LGPL|EUPL|CDDL|CPAL|OSL|SSPL|RPL)\b",
    re.IGNORECASE,
)
RESTRICTED_PATTERNS = re.compile(
    r"\b(Commercial|Proprietary|Unknown|UNLICENSED|No License)\b",
    re.IGNORECASE,
)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
MAVEN_PKG_PATTERN = re.compile(
    r"^pkg:maven/(?P<group>[^/]+)/(?P<artifact>[^@]+)@(?P<version>.+)$"
)


@dataclass
class MetricResult:
    classification: str
    technique: str
    metric: str
    raw_value: float
    normalised_score: float
    threshold: str
    result: str
    derivation: str
    formula: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanReport:
    tool: str
    report_path: str
    total_components: int
    total_vulnerabilities: int
    distinct_cves: int
    metrics: list[MetricResult]
    dependencies: list[dict[str, Any]] = field(default_factory=list)


def _clamp_score(value: float) -> float:
    return max(0.0, min(100.0, round(value, 2)))


def _pass_from_score(score: float, *, gate_at_100: bool = False) -> str:
    if gate_at_100:
        return "PASS" if score >= 100.0 else "FAIL"
    return "PASS" if score >= 70.0 else "FAIL"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _is_component(dep: dict[str, Any]) -> bool:
    if dep.get("isVirtual"):
        return False
    file_name = str(dep.get("fileName", "")).lower()
    return file_name.endswith(".jar") or bool(dep.get("packages"))


def _is_transitive(dep: dict[str, Any]) -> bool:
    included_by = dep.get("includedBy") or []
    return len(included_by) > 0


def _dependency_version(dep: dict[str, Any]) -> str | None:
    for package in dep.get("packages") or []:
        package_id = str(package.get("id", ""))
        match = MAVEN_PKG_PATTERN.match(package_id)
        if match:
            return match.group("version")
    for evidence in (dep.get("evidenceCollected") or {}).get("versionEvidence") or []:
        value = str(evidence.get("value", "")).strip()
        if value:
            return value
    return None


def _dependency_license(dep: dict[str, Any]) -> str:
    license_value = dep.get("license")
    if license_value:
        return str(license_value)
    for evidence in (dep.get("evidenceCollected") or {}).get("vendorEvidence") or []:
        if str(evidence.get("name", "")).lower() == "license":
            return str(evidence.get("value", ""))
    return "Unknown"


def _vulnerability_severity(vuln: dict[str, Any]) -> str:
    for key in ("severity",):
        severity = vuln.get(key)
        if severity:
            return str(severity).upper()
    for cvss_key in ("cvssV4", "cvssV3", "cvssV2"):
        cvss = vuln.get(cvss_key) or {}
        cvss_data = cvss.get("cvssData") or {}
        severity = cvss_data.get("baseSeverity")
        if severity:
            return str(severity).upper()
    score = _vulnerability_cvss(vuln)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"


def _vulnerability_cvss(vuln: dict[str, Any]) -> float:
    for cvss_key in ("cvssV4", "cvssV3", "cvssV2"):
        cvss = vuln.get(cvss_key) or {}
        cvss_data = cvss.get("cvssData") or {}
        score = cvss_data.get("baseScore")
        if score is not None:
            try:
                return float(score)
            except (TypeError, ValueError):
                continue
    return 0.0


def _vulnerability_has_fix(vuln: dict[str, Any]) -> bool:
    if vuln.get("knownExploitedVulnerability"):
        return True
    description = str(vuln.get("description", "")).lower()
    fix_markers = (
        "fixed in",
        "upgrade to",
        "update to",
        "patched in",
        "resolved in",
        "remediation",
    )
    return any(marker in description for marker in fix_markers)


def _package_confidence(dep: dict[str, Any]) -> str:
    packages = dep.get("packages") or []
    if not packages:
        return "LOW"
    confidences = [str(pkg.get("confidence", "LOW")).upper() for pkg in packages]
    if "HIGHEST" in confidences or "HIGH" in confidences:
        return "HIGH"
    if "MEDIUM" in confidences:
        return "MEDIUM"
    return confidences[0] if confidences else "LOW"


def _parse_major_version(version: str | None) -> int | None:
    if not version:
        return None
    match = re.match(r"(\d+)", version)
    if not match:
        return None
    return int(match.group(1))


def _parse_version_updates(path: Path | None) -> dict[str, str]:
    """Parse versions-maven-plugin dependency-updates report if present."""
    if path is None or not path.exists():
        return {}
    latest: dict[str, str] = {}
    current_key: str | None = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("The following dependencies in Dependencies have newer versions:"):
            continue
        artifact_match = re.match(r"^\s+(.+?) \.+ (.+)$", line)
        if artifact_match:
            current_key = artifact_match.group(1).strip()
            latest[current_key] = artifact_match.group(2).strip()
    return latest


def _major_version_lag(current: str | None, latest: str | None) -> int:
    current_major = _parse_major_version(current)
    latest_major = _parse_major_version(latest)
    if current_major is None or latest_major is None:
        return 0
    return max(0, latest_major - current_major)


def _collect_cve_ids(report: dict[str, Any]) -> set[str]:
    cves: set[str] = set()
    for dep in report.get("dependencies") or []:
        for vuln in dep.get("vulnerabilities") or []:
            name = str(vuln.get("name", ""))
            if CVE_PATTERN.match(name):
                cves.add(name.upper())
    return cves


def _load_baseline(path: Path | None) -> set[str]:
    if path is None or not path.exists():
        return set()
    data = _load_json(path)
    return {str(item).upper() for item in data.get("cves", [])}


def compute_metrics(
    report_path: Path,
    *,
    version_updates_path: Path | None = None,
    baseline_path: Path | None = None,
) -> ScanReport:
    report = _load_json(report_path)
    dependencies = [dep for dep in report.get("dependencies") or [] if _is_component(dep)]
    components = dependencies
    component_count = len(components)
    transitive_components = [dep for dep in components if _is_transitive(dep)]
    vulnerable_components = [
        dep for dep in components if dep.get("vulnerabilities")
    ]
    vulnerable_transitive = [
        dep
        for dep in transitive_components
        if dep.get("vulnerabilities")
    ]
    flagged_transitive = [
        dep
        for dep in transitive_components
        if _package_confidence(dep) in {"LOW", "MEDIUM"}
    ]

    transitive_risk_score = len(vulnerable_transitive) * 20 + len(flagged_transitive) * 5
    hidden_score = _clamp_score(100 - transitive_risk_score)
    hidden_ratio = (
        len(transitive_components) / component_count if component_count else 0.0
    )

    copyleft_deps = [
        dep
        for dep in components
        if COPYLEFT_PATTERNS.search(_dependency_license(dep))
    ]
    restricted_deps = [
        dep
        for dep in components
        if RESTRICTED_PATTERNS.search(_dependency_license(dep))
    ]
    license_risk = len(copyleft_deps) * 20 + len(restricted_deps) * 10
    legal_score = _clamp_score(100 - license_risk)
    license_ratio = (
        (len(copyleft_deps) + len(restricted_deps)) / component_count
        if component_count
        else 0.0
    )

    unverified_sources = [
        dep for dep in components if _package_confidence(dep) in {"LOW", "MEDIUM"}
    ]
    deprecated_registries = [
        dep
        for dep in components
        if any(
            "deprecated" in str(pkg.get("notes", "")).lower()
            for pkg in dep.get("packages") or []
        )
    ]
    trust_score = len(unverified_sources) * 25 + len(deprecated_registries) * 10
    trust_normalised = _clamp_score(100 - trust_score)
    vulnerability_matches = sum(
        len(dep.get("vulnerabilities") or []) for dep in components
    )
    critical_matches = sum(
        1
        for dep in components
        for vuln in dep.get("vulnerabilities") or []
        if _vulnerability_severity(vuln) == "CRITICAL"
    )
    vulnerability_density = (
        vulnerability_matches / component_count if component_count else 0.0
    )
    critical_ratio = (
        critical_matches / vulnerability_matches if vulnerability_matches else 0.0
    )

    version_updates = _parse_version_updates(version_updates_path)
    outdated_components: list[dict[str, Any]] = []
    major_lag_two_plus = 0
    major_lag_one = 0
    for dep in components:
        current = _dependency_version(dep)
        package_name = None
        for package in dep.get("packages") or []:
            package_id = str(package.get("id", ""))
            match = MAVEN_PKG_PATTERN.match(package_id)
            if match:
                package_name = f"{match.group('group')}:{match.group('artifact')}"
                break
        latest = version_updates.get(package_name or "", current)
        if current and latest and current != latest:
            outdated_components.append(dep)
        lag = _major_version_lag(current, latest)
        if lag >= 2:
            major_lag_two_plus += 1
        elif lag == 1:
            major_lag_one += 1

    abandoned_deps = [
        dep
        for dep in components
        if dep.get("vulnerabilities")
        and not any(
            _vulnerability_has_fix(vuln)
            for vuln in dep.get("vulnerabilities") or []
        )
    ]
    low_activity_deps = outdated_components
    vitality_score = len(abandoned_deps) * 20 + len(low_activity_deps) * 5
    vitality_normalised = _clamp_score(100 - vitality_score)
    health_ratio = (
        (component_count - len(outdated_components)) / component_count
        if component_count
        else 1.0
    )

    critical_high_deps: list[dict[str, Any]] = []
    critical_high_with_fix = 0
    severity_weights = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 1}
    weighted_total = 0.0
    for dep in components:
        severities = [
            _vulnerability_severity(vuln)
            for vuln in dep.get("vulnerabilities") or []
        ]
        if not severities:
            continue
        weighted_total += sum(severity_weights.get(sev, 1) for sev in severities)
        if any(sev in {"CRITICAL", "HIGH"} for sev in severities):
            critical_high_deps.append(dep)
            if any(
                _vulnerability_has_fix(vuln)
                for vuln in dep.get("vulnerabilities") or []
            ):
                critical_high_with_fix += 1
    if critical_high_deps:
        prioritization_coverage = (critical_high_with_fix / len(critical_high_deps)) * 100
    else:
        prioritization_coverage = 100.0
    prioritization_score = _clamp_score(prioritization_coverage)
    weighted_vulnerability_score = (
        weighted_total / vulnerability_matches if vulnerability_matches else 0.0
    )

    current_cves = _collect_cve_ids(report)
    baseline_cves = _load_baseline(baseline_path)
    new_cves = sorted(current_cves - baseline_cves)
    if baseline_cves:
        alert_response_rate = 0.0 if new_cves else 100.0
    else:
        alert_response_rate = 100.0 if not new_cves else 0.0
    alert_score = _clamp_score(alert_response_rate)
    alert_density = (
        len(new_cves) / component_count if component_count else 0.0
    )

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    distinct_cves: set[str] = set()
    fixes_available = 0
    for dep in components:
        for vuln in dep.get("vulnerabilities") or []:
            severity = _vulnerability_severity(vuln)
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            name = str(vuln.get("name", ""))
            if CVE_PATTERN.match(name):
                distinct_cves.add(name.upper())
            if _vulnerability_has_fix(vuln):
                fixes_available += 1
    cve_score_raw = (
        severity_counts["CRITICAL"] * 25
        + severity_counts["HIGH"] * 10
        + severity_counts["MEDIUM"] * 3
        + severity_counts["LOW"] * 1
    )
    cve_normalised = _clamp_score(100 - cve_score_raw)
    fix_availability_ratio = (
        fixes_available / vulnerability_matches if vulnerability_matches else 1.0
    )

    version_lag_score_raw = major_lag_two_plus * 15 + major_lag_one * 5
    version_lag_normalised = _clamp_score(100 - version_lag_score_raw)
    version_lag_ratio = (
        len(outdated_components) / component_count if component_count else 0.0
    )

    metrics = [
        MetricResult(
            classification="Hidden Relationship Mapping",
            technique="Transitive Dependency Analysis",
            metric="Hidden Relationship Mapping",
            raw_value=transitive_risk_score,
            normalised_score=hidden_score,
            threshold="0 vulnerable transitive dependencies in resolved tree",
            result=_pass_from_score(hidden_score),
            derivation=(
                "Hidden Dependency Ratio = count(transitive components) / count(components); "
                f"ratio={hidden_ratio:.4f}"
            ),
            formula=(
                "Transitive Risk Score = Count(Vulnerable Transitive Deps)×20 + "
                "Count(Flagged Transitive Deps)×5"
            ),
            details={
                "transitive_components": len(transitive_components),
                "vulnerable_transitive": len(vulnerable_transitive),
                "flagged_transitive": len(flagged_transitive),
                "hidden_dependency_ratio": round(hidden_ratio, 4),
            },
        ),
        MetricResult(
            classification="Legal Risk Validation",
            technique="License Compliance Testing",
            metric="Legal Risk Validation",
            raw_value=license_risk,
            normalised_score=legal_score,
            threshold="0 copyleft licenses in production dependencies",
            result=_pass_from_score(legal_score),
            derivation=(
                "License Risk Score = count(copyleft + restricted) / count(packages); "
                f"ratio={license_ratio:.4f}"
            ),
            formula="License Risk = Count(Copyleft Deps)×20 + Count(Restricted Deps)×10",
            details={
                "copyleft_dependencies": len(copyleft_deps),
                "restricted_dependencies": len(restricted_deps),
                "license_risk_ratio": round(license_ratio, 4),
            },
        ),
        MetricResult(
            classification="Trust Integrity Verification",
            technique="Supply Chain Security Analysis",
            metric="Trust Integrity Verification",
            raw_value=trust_score,
            normalised_score=trust_normalised,
            threshold="0 packages from unverified or deprecated sources",
            result=_pass_from_score(trust_normalised),
            derivation=(
                "Vulnerability Density = count(matches)/count(components); "
                f"density={vulnerability_density:.4f}; "
                f"Critical Ratio={critical_ratio:.4f}"
            ),
            formula=(
                "Trust Score = Count(Unverified Package Sources)×25 + "
                "Count(Deprecated Registries)×10"
            ),
            details={
                "unverified_package_sources": len(unverified_sources),
                "deprecated_registries": len(deprecated_registries),
                "vulnerability_density": round(vulnerability_density, 4),
                "critical_vulnerability_ratio": round(critical_ratio, 4),
            },
        ),
        MetricResult(
            classification="Community Vitality Tracking",
            technique="Dependency Health Monitoring",
            metric="Community Vitality Tracking",
            raw_value=vitality_score,
            normalised_score=vitality_normalised,
            threshold="0 abandoned dependencies in production stack",
            result=_pass_from_score(vitality_normalised),
            derivation=(
                "Dependency Health = count(current==latest)/count(dependencies); "
                f"ratio={health_ratio:.4f}"
            ),
            formula=(
                "Vitality Score = Count(Abandoned Deps)×20 + Count(Low-activity Deps)×5"
            ),
            details={
                "abandoned_dependencies": len(abandoned_deps),
                "low_activity_dependencies": len(low_activity_deps),
                "health_ratio": round(health_ratio, 4),
            },
        ),
        MetricResult(
            classification="Mitigation Effort Ranking",
            technique="Risk Prioritization",
            metric="Mitigation Effort Ranking",
            raw_value=prioritization_coverage,
            normalised_score=prioritization_score,
            threshold="100% of Critical/High CVE deps have assigned remediation",
            result=_pass_from_score(prioritization_score, gate_at_100=True),
            derivation=(
                "Weighted Vulnerability Score = sum(weight(severity))/count(matches); "
                f"weighted={weighted_vulnerability_score:.4f}"
            ),
            formula=(
                "Prioritization Coverage % = "
                "(Critical/High CVE Deps with assigned fix / Total Critical/High CVE Deps)×100"
            ),
            details={
                "critical_high_dependencies": len(critical_high_deps),
                "critical_high_with_fix": critical_high_with_fix,
                "prioritization_coverage_percent": round(prioritization_coverage, 2),
                "weighted_vulnerability_score": round(weighted_vulnerability_score, 4),
            },
        ),
        MetricResult(
            classification="Real-Time Alerting",
            technique="Continuous Dependency Monitoring",
            metric="Real-Time Alerting",
            raw_value=alert_response_rate,
            normalised_score=alert_score,
            threshold="100% of new CVE alerts actioned within SLA",
            result=_pass_from_score(alert_score, gate_at_100=True),
            derivation=(
                "Alert Density = count(new security advisories)/count(components); "
                f"density={alert_density:.4f}"
            ),
            formula=(
                "Alert Response Rate % = "
                "(New CVE Alerts Actioned within SLA / Total New CVE Alerts)×100"
            ),
            details={
                "new_cves": new_cves,
                "baseline_cve_count": len(baseline_cves),
                "current_cve_count": len(current_cves),
                "alert_density": round(alert_density, 4),
            },
        ),
        MetricResult(
            classification="Known CVE Count",
            technique="Vulnerability Dependency Detection",
            metric="Known CVE Count",
            raw_value=cve_score_raw,
            normalised_score=cve_normalised,
            threshold="0 Critical CVEs; 0 High CVEs in production dependencies",
            result=_pass_from_score(cve_normalised),
            derivation=(
                "Known CVE Count = count(distinct vulnerability.id); "
                f"count={len(distinct_cves)}; "
                f"Fix Availability Ratio={fix_availability_ratio:.4f}"
            ),
            formula=(
                "CVE Score = Count(Crit)×25 + Count(High)×10 + "
                "Count(Med)×3 + Count(Low)×1"
            ),
            details={
                "distinct_cve_count": len(distinct_cves),
                "severity_counts": severity_counts,
                "fix_availability_ratio": round(fix_availability_ratio, 4),
            },
        ),
        MetricResult(
            classification="Version Lag Assessment",
            technique="Outdated Dependency Detection",
            metric="Version Lag Assessment",
            raw_value=version_lag_score_raw,
            normalised_score=version_lag_normalised,
            threshold="0 dependencies more than 2 major versions behind",
            result=_pass_from_score(version_lag_normalised),
            derivation=(
                "Version Lag Score = count(current!=latest)/count(dependencies); "
                f"ratio={version_lag_ratio:.4f}"
            ),
            formula=(
                "Version Lag Score = Count(Deps >2 major versions behind)×15 + "
                "Count(Deps 1 major version behind)×5"
            ),
            details={
                "outdated_dependencies": len(outdated_components),
                "major_lag_two_plus": major_lag_two_plus,
                "major_lag_one": major_lag_one,
                "version_lag_ratio": round(version_lag_ratio, 4),
            },
        ),
    ]

    return ScanReport(
        tool=TOOL,
        report_path=str(report_path),
        total_components=component_count,
        total_vulnerabilities=vulnerability_matches,
        distinct_cves=len(distinct_cves),
        metrics=metrics,
        dependencies=components,
    )


def build_testable_gate_report(report: ScanReport) -> dict[str, Any]:
    return {
        "gate_name": GATE_NAME,
        "tool": report.tool,
        "execution_status": "COMPLETED",
        "total_components": report.total_components,
        "total_vulnerabilities": report.total_vulnerabilities,
        "distinct_cves": report.distinct_cves,
        "all_gates_passed": all(metric.result == "PASS" for metric in report.metrics),
        "metrics": [
            {
                "classification": metric.classification,
                "technique": metric.technique,
                "value": metric.normalised_score,
                "raw_value": metric.raw_value,
                "result": metric.result,
                "coverage": metric.normalised_score,
                "execution_status": "COMPLETED",
                "threshold": metric.threshold,
                "derivation": metric.derivation,
                "formula": metric.formula,
                "details": metric.details,
            }
            for metric in report.metrics
        ],
    }


def build_platform_dependency_check_json(
    report: ScanReport,
    gate_report: dict[str, Any],
    *,
    report_path: str,
) -> dict[str, Any]:
    platform: dict[str, Any] = {
        "exit": 0,
        "scan_ok": True,
        "report_path": report_path,
        "total_components": report.total_components,
        "total_vulnerabilities": report.total_vulnerabilities,
        "distinct_cves": report.distinct_cves,
        "gate_name": GATE_NAME,
        "tool": TOOL,
        "execution_status": "COMPLETED",
        "all_gates_passed": gate_report["all_gates_passed"],
        "scoring_policy": "Excel normalisation formulas from Dependency-Check JSON report",
        "metrics": [
            {
                "classification": metric.classification,
                "value": metric.normalised_score,
                "execution_status": "COMPLETED",
                "result": metric.result,
                "coverage": metric.normalised_score,
            }
            for metric in report.metrics
        ],
    }
    for classification, key in CLASSIFICATION_TO_PLATFORM_KEY.items():
        metric = next(m for m in report.metrics if m.classification == classification)
        platform[key] = metric.normalised_score
    return platform


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# OWASP Dependency-Check SCA Metrics Report",
        "",
        f"- Tool: **{report.tool}**",
        f"- Components scanned: **{report.total_components}**",
        f"- Vulnerability matches: **{report.total_vulnerabilities}**",
        f"- Distinct CVEs: **{report.distinct_cves}**",
        "",
        "| Classification | Technique | Score | Result | Threshold |",
        "| --- | --- | ---: | --- | --- |",
    ]
    for metric in report.metrics:
        lines.append(
            f"| {metric.classification} | {metric.technique} | "
            f"{metric.normalised_score:.2f} | {metric.result} | {metric.threshold} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--report",
        default="target/dependency-check/dependency-check-report.json",
        help="Path to dependency-check JSON report",
    )
    parser.add_argument(
        "--version-updates",
        default="target/dependency-updates.txt",
        help="Optional versions-maven-plugin updates report",
    )
    parser.add_argument(
        "--baseline",
        default="baseline/cve_snapshot.json",
        help="Optional baseline CVE snapshot for alerting metric",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    report_path = root / args.report
    version_updates_path = root / args.version_updates
    baseline_path = root / args.baseline

    if not report_path.exists():
        print(f"Missing Dependency-Check report: {report_path}")
        return 2

    scan_report = compute_metrics(
        report_path,
        version_updates_path=version_updates_path if version_updates_path.exists() else None,
        baseline_path=baseline_path if baseline_path.exists() else None,
    )
    print(render_markdown(scan_report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
