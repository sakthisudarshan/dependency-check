package com.testable.metrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public final class MetricsReporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Pattern COPYLEFT = Pattern.compile(
            "\\b(GPL|AGPL|LGPL|EUPL|CDDL|CPAL|OSL|SSPL|RPL)\\b",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern RESTRICTED = Pattern.compile(
            "\\b(Commercial|Proprietary|Unknown|UNLICENSED|No License)\\b",
            Pattern.CASE_INSENSITIVE
    );
    private static final Pattern CVE = Pattern.compile("^CVE-\\d{4}-\\d+$", Pattern.CASE_INSENSITIVE);
    private static final Pattern MAVEN_PKG = Pattern.compile(
            "^pkg:maven/(?<group>[^/]+)/(?<artifact>[^@]+)@(?<version>.+)$"
    );
    private static final Pattern VERSION_UPDATES = Pattern.compile("^\\s+(.+?) \\.+ (.+)$");
    private static final Pattern MAJOR_VERSION = Pattern.compile("^(\\d+)");

    private MetricsReporter() {
    }

    public static ScanReport computeMetrics(
            Path reportPath,
            Path versionUpdatesPath,
            Path baselinePath
    ) throws IOException {
        JsonNode report = MAPPER.readTree(reportPath.toFile());
        List<JsonNode> components = StreamSupport.stream(report.path("dependencies").spliterator(), false)
                .filter(MetricsReporter::isComponent)
                .collect(Collectors.toList());

        int componentCount = components.size();
        List<JsonNode> transitive = components.stream().filter(MetricsReporter::isTransitive).toList();
        List<JsonNode> vulnerableTransitive = transitive.stream()
                .filter(dep -> dep.has("vulnerabilities") && dep.path("vulnerabilities").size() > 0)
                .toList();
        List<JsonNode> flaggedTransitive = transitive.stream()
                .filter(dep -> {
                    String confidence = packageConfidence(dep);
                    return "LOW".equals(confidence) || "MEDIUM".equals(confidence);
                })
                .toList();

        int transitiveRiskScore = vulnerableTransitive.size() * 20 + flaggedTransitive.size() * 5;
        double hiddenScore = clamp(100 - transitiveRiskScore);
        double hiddenRatio = componentCount == 0 ? 0.0 : (double) transitive.size() / componentCount;

        List<JsonNode> copyleftDeps = components.stream()
                .filter(dep -> COPYLEFT.matcher(dependencyLicense(dep)).find())
                .toList();
        List<JsonNode> restrictedDeps = components.stream()
                .filter(dep -> RESTRICTED.matcher(dependencyLicense(dep)).find())
                .toList();
        int licenseRisk = copyleftDeps.size() * 20 + restrictedDeps.size() * 10;
        double legalScore = clamp(100 - licenseRisk);
        double licenseRatio = componentCount == 0
                ? 0.0
                : (double) (copyleftDeps.size() + restrictedDeps.size()) / componentCount;

        List<JsonNode> unverified = components.stream()
                .filter(dep -> {
                    String confidence = packageConfidence(dep);
                    return "LOW".equals(confidence) || "MEDIUM".equals(confidence);
                })
                .toList();
        List<JsonNode> deprecated = components.stream()
                .filter(dep -> StreamSupport.stream(dep.path("packages").spliterator(), false)
                        .anyMatch(pkg -> pkg.path("notes").asText("").toLowerCase().contains("deprecated")))
                .toList();
        int trustScore = unverified.size() * 25 + deprecated.size() * 10;
        double trustScoreNorm = clamp(100 - trustScore);

        int vulnerabilityMatches = components.stream()
                .mapToInt(dep -> dep.path("vulnerabilities").size())
                .sum();
        int criticalMatches = (int) components.stream()
                .flatMap(dep -> StreamSupport.stream(dep.path("vulnerabilities").spliterator(), false))
                .filter(vuln -> "CRITICAL".equals(vulnerabilitySeverity(vuln)))
                .count();
        double vulnerabilityDensity = componentCount == 0 ? 0.0 : (double) vulnerabilityMatches / componentCount;
        double criticalRatio = vulnerabilityMatches == 0 ? 0.0 : (double) criticalMatches / vulnerabilityMatches;

        Map<String, String> versionUpdates = parseVersionUpdates(versionUpdatesPath);
        List<JsonNode> outdated = new ArrayList<>();
        int majorLagTwoPlus = 0;
        int majorLagOne = 0;
        for (JsonNode dep : components) {
            String current = dependencyVersion(dep);
            String packageName = packageCoordinate(dep);
            String latest = versionUpdates.getOrDefault(packageName == null ? "" : packageName, current);
            if (current != null && latest != null && !current.equals(latest)) {
                outdated.add(dep);
            }
            int lag = majorVersionLag(current, latest);
            if (lag >= 2) {
                majorLagTwoPlus++;
            } else if (lag == 1) {
                majorLagOne++;
            }
        }

        List<JsonNode> abandoned = components.stream()
                .filter(dep -> dep.has("vulnerabilities") && dep.path("vulnerabilities").size() > 0)
                .filter(dep -> StreamSupport.stream(dep.path("vulnerabilities").spliterator(), false)
                        .noneMatch(MetricsReporter::vulnerabilityHasFix))
                .toList();
        int vitalityScore = abandoned.size() * 20 + outdated.size() * 5;
        double vitalityNorm = clamp(100 - vitalityScore);
        double healthRatio = componentCount == 0
                ? 1.0
                : (double) (componentCount - outdated.size()) / componentCount;

        List<JsonNode> criticalHighDeps = new ArrayList<>();
        int criticalHighWithFix = 0;
        Map<String, Integer> severityWeights = Map.of(
                "CRITICAL", 4, "HIGH", 3, "MEDIUM", 2, "LOW", 1, "UNKNOWN", 1
        );
        double weightedTotal = 0.0;
        for (JsonNode dep : components) {
            List<String> severities = StreamSupport.stream(dep.path("vulnerabilities").spliterator(), false)
                    .map(MetricsReporter::vulnerabilitySeverity)
                    .toList();
            if (severities.isEmpty()) {
                continue;
            }
            for (String severity : severities) {
                weightedTotal += severityWeights.getOrDefault(severity, 1);
            }
            if (severities.stream().anyMatch(sev -> "CRITICAL".equals(sev) || "HIGH".equals(sev))) {
                criticalHighDeps.add(dep);
                boolean hasFix = StreamSupport.stream(dep.path("vulnerabilities").spliterator(), false)
                        .anyMatch(MetricsReporter::vulnerabilityHasFix);
                if (hasFix) {
                    criticalHighWithFix++;
                }
            }
        }
        double prioritizationCoverage = criticalHighDeps.isEmpty()
                ? 100.0
                : (double) criticalHighWithFix / criticalHighDeps.size() * 100.0;
        double prioritizationScore = clamp(prioritizationCoverage);
        double weightedVulnerabilityScore = vulnerabilityMatches == 0 ? 0.0 : weightedTotal / vulnerabilityMatches;

        Set<String> currentCves = collectCveIds(report);
        Set<String> baselineCves = loadBaseline(baselinePath);
        Set<String> newCves = new HashSet<>(currentCves);
        newCves.removeAll(baselineCves);
        double alertResponseRate;
        if (!baselineCves.isEmpty()) {
            alertResponseRate = newCves.isEmpty() ? 100.0 : 0.0;
        } else {
            alertResponseRate = newCves.isEmpty() ? 100.0 : 0.0;
        }
        double alertScore = clamp(alertResponseRate);
        double alertDensity = componentCount == 0 ? 0.0 : (double) newCves.size() / componentCount;

        Map<String, Integer> severityCounts = new LinkedHashMap<>();
        severityCounts.put("CRITICAL", 0);
        severityCounts.put("HIGH", 0);
        severityCounts.put("MEDIUM", 0);
        severityCounts.put("LOW", 0);
        severityCounts.put("UNKNOWN", 0);
        Set<String> distinctCves = new HashSet<>();
        int fixesAvailable = 0;
        for (JsonNode dep : components) {
            for (JsonNode vuln : dep.path("vulnerabilities")) {
                String severity = vulnerabilitySeverity(vuln);
                severityCounts.put(severity, severityCounts.getOrDefault(severity, 0) + 1);
                String name = vuln.path("name").asText("");
                if (CVE.matcher(name).matches()) {
                    distinctCves.add(name.toUpperCase());
                }
                if (vulnerabilityHasFix(vuln)) {
                    fixesAvailable++;
                }
            }
        }
        int cveScoreRaw = severityCounts.get("CRITICAL") * 25
                + severityCounts.get("HIGH") * 10
                + severityCounts.get("MEDIUM") * 3
                + severityCounts.get("LOW");
        double cveNorm = clamp(100 - cveScoreRaw);
        double fixAvailabilityRatio = vulnerabilityMatches == 0 ? 1.0 : (double) fixesAvailable / vulnerabilityMatches;

        int versionLagScoreRaw = majorLagTwoPlus * 15 + majorLagOne * 5;
        double versionLagNorm = clamp(100 - versionLagScoreRaw);
        double versionLagRatio = componentCount == 0 ? 0.0 : (double) outdated.size() / componentCount;

        List<MetricResult> metrics = List.of(
                metric(
                        "Hidden Relationship Mapping",
                        "Transitive Dependency Analysis",
                        transitiveRiskScore,
                        hiddenScore,
                        "0 vulnerable transitive dependencies in resolved tree",
                        "Hidden Dependency Ratio = count(transitive components) / count(components); ratio="
                                + String.format("%.4f", hiddenRatio),
                        "Transitive Risk Score = Count(Vulnerable Transitive Deps)×20 + Count(Flagged Transitive Deps)×5",
                        Map.of(
                                "transitive_components", transitive.size(),
                                "vulnerable_transitive", vulnerableTransitive.size(),
                                "flagged_transitive", flaggedTransitive.size(),
                                "hidden_dependency_ratio", round(hiddenRatio, 4)
                        )
                ),
                metric(
                        "Legal Risk Validation",
                        "License Compliance Testing",
                        licenseRisk,
                        legalScore,
                        "0 copyleft licenses in production dependencies",
                        "License Risk Score = count(copyleft + restricted) / count(packages); ratio="
                                + String.format("%.4f", licenseRatio),
                        "License Risk = Count(Copyleft Deps)×20 + Count(Restricted Deps)×10",
                        Map.of(
                                "copyleft_dependencies", copyleftDeps.size(),
                                "restricted_dependencies", restrictedDeps.size(),
                                "license_risk_ratio", round(licenseRatio, 4)
                        )
                ),
                metric(
                        "Trust Integrity Verification",
                        "Supply Chain Security Analysis",
                        trustScore,
                        trustScoreNorm,
                        "0 packages from unverified or deprecated sources",
                        "Vulnerability Density = count(matches)/count(components); density="
                                + String.format("%.4f", vulnerabilityDensity)
                                + "; Critical Ratio=" + String.format("%.4f", criticalRatio),
                        "Trust Score = Count(Unverified Package Sources)×25 + Count(Deprecated Registries)×10",
                        Map.of(
                                "unverified_package_sources", unverified.size(),
                                "deprecated_registries", deprecated.size(),
                                "vulnerability_density", round(vulnerabilityDensity, 4),
                                "critical_vulnerability_ratio", round(criticalRatio, 4)
                        )
                ),
                metric(
                        "Community Vitality Tracking",
                        "Dependency Health Monitoring",
                        vitalityScore,
                        vitalityNorm,
                        "0 abandoned dependencies in production stack",
                        "Dependency Health = count(current==latest)/count(dependencies); ratio="
                                + String.format("%.4f", healthRatio),
                        "Vitality Score = Count(Abandoned Deps)×20 + Count(Low-activity Deps)×5",
                        Map.of(
                                "abandoned_dependencies", abandoned.size(),
                                "low_activity_dependencies", outdated.size(),
                                "health_ratio", round(healthRatio, 4)
                        )
                ),
                metric(
                        "Mitigation Effort Ranking",
                        "Risk Prioritization",
                        prioritizationCoverage,
                        prioritizationScore,
                        "100% of Critical/High CVE deps have assigned remediation",
                        "Weighted Vulnerability Score = sum(weight(severity))/count(matches); weighted="
                                + String.format("%.4f", weightedVulnerabilityScore),
                        "Prioritization Coverage % = (Critical/High CVE Deps with assigned fix / Total Critical/High CVE Deps)×100",
                        Map.of(
                                "critical_high_dependencies", criticalHighDeps.size(),
                                "critical_high_with_fix", criticalHighWithFix,
                                "prioritization_coverage_percent", round(prioritizationCoverage, 2),
                                "weighted_vulnerability_score", round(weightedVulnerabilityScore, 4)
                        ),
                        true
                ),
                metric(
                        "Real-Time Alerting",
                        "Continuous Dependency Monitoring",
                        alertResponseRate,
                        alertScore,
                        "100% of new CVE alerts actioned within SLA",
                        "Alert Density = count(new security advisories)/count(components); density="
                                + String.format("%.4f", alertDensity),
                        "Alert Response Rate % = (New CVE Alerts Actioned within SLA / Total New CVE Alerts)×100",
                        Map.of(
                                "new_cves", newCves.stream().sorted().toList(),
                                "baseline_cve_count", baselineCves.size(),
                                "current_cve_count", currentCves.size(),
                                "alert_density", round(alertDensity, 4)
                        ),
                        true
                ),
                metric(
                        "Known CVE Count",
                        "Vulnerability Dependency Detection",
                        cveScoreRaw,
                        cveNorm,
                        "0 Critical CVEs; 0 High CVEs in production dependencies",
                        "Known CVE Count = count(distinct vulnerability.id); count="
                                + distinctCves.size()
                                + "; Fix Availability Ratio=" + String.format("%.4f", fixAvailabilityRatio),
                        "CVE Score = Count(Crit)×25 + Count(High)×10 + Count(Med)×3 + Count(Low)×1",
                        Map.of(
                                "distinct_cve_count", distinctCves.size(),
                                "severity_counts", severityCounts,
                                "fix_availability_ratio", round(fixAvailabilityRatio, 4)
                        )
                ),
                metric(
                        "Version Lag Assessment",
                        "Outdated Dependency Detection",
                        versionLagScoreRaw,
                        versionLagNorm,
                        "0 dependencies more than 2 major versions behind",
                        "Version Lag Score = count(current!=latest)/count(dependencies); ratio="
                                + String.format("%.4f", versionLagRatio),
                        "Version Lag Score = Count(Deps >2 major versions behind)×15 + Count(Deps 1 major version behind)×5",
                        Map.of(
                                "outdated_dependencies", outdated.size(),
                                "major_lag_two_plus", majorLagTwoPlus,
                                "major_lag_one", majorLagOne,
                                "version_lag_ratio", round(versionLagRatio, 4)
                        )
                )
        );

        return new ScanReport(
                MetricsConstants.TOOL,
                reportPath.toString(),
                componentCount,
                vulnerabilityMatches,
                distinctCves.size(),
                metrics,
                components
        );
    }

    private static MetricResult metric(
            String classification,
            String technique,
            double rawValue,
            double normalisedScore,
            String threshold,
            String derivation,
            String formula,
            Map<String, Object> details
    ) {
        return metric(classification, technique, rawValue, normalisedScore, threshold, derivation, formula, details, false);
    }

    private static MetricResult metric(
            String classification,
            String technique,
            double rawValue,
            double normalisedScore,
            String threshold,
            String derivation,
            String formula,
            Map<String, Object> details,
            boolean gateAt100
    ) {
        return new MetricResult(
                classification,
                technique,
                classification,
                rawValue,
                normalisedScore,
                threshold,
                passFromScore(normalisedScore, gateAt100),
                derivation,
                formula,
                details
        );
    }

    private static double clamp(double value) {
        return Math.max(0.0, Math.min(100.0, Math.round(value * 100.0) / 100.0));
    }

    private static double round(double value, int places) {
        double factor = Math.pow(10, places);
        return Math.round(value * factor) / factor;
    }

    private static String passFromScore(double score, boolean gateAt100) {
        if (gateAt100) {
            return score >= 100.0 ? "PASS" : "FAIL";
        }
        return score >= 70.0 ? "PASS" : "FAIL";
    }

    private static boolean isComponent(JsonNode dep) {
        if (dep.path("isVirtual").asBoolean(false)) {
            return false;
        }
        String fileName = dep.path("fileName").asText("").toLowerCase();
        return fileName.endsWith(".jar") || dep.has("packages");
    }

    private static boolean isTransitive(JsonNode dep) {
        return dep.has("includedBy") && dep.path("includedBy").size() > 0;
    }

    private static String dependencyVersion(JsonNode dep) {
        for (JsonNode pkg : dep.path("packages")) {
            Matcher matcher = MAVEN_PKG.matcher(pkg.path("id").asText(""));
            if (matcher.matches()) {
                return matcher.group("version");
            }
        }
        for (JsonNode evidence : dep.path("evidenceCollected").path("versionEvidence")) {
            String value = evidence.path("value").asText("").trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        return null;
    }

    private static String packageCoordinate(JsonNode dep) {
        for (JsonNode pkg : dep.path("packages")) {
            Matcher matcher = MAVEN_PKG.matcher(pkg.path("id").asText(""));
            if (matcher.matches()) {
                return matcher.group("group") + ":" + matcher.group("artifact");
            }
        }
        return null;
    }

    private static String dependencyLicense(JsonNode dep) {
        if (dep.hasNonNull("license")) {
            return dep.path("license").asText();
        }
        for (JsonNode evidence : dep.path("evidenceCollected").path("vendorEvidence")) {
            if ("license".equalsIgnoreCase(evidence.path("name").asText())) {
                return evidence.path("value").asText("");
            }
        }
        return "Unknown";
    }

    private static String vulnerabilitySeverity(JsonNode vuln) {
        if (vuln.hasNonNull("severity")) {
            return vuln.path("severity").asText("").toUpperCase();
        }
        for (String cvssKey : List.of("cvssV4", "cvssV3", "cvssV2")) {
            JsonNode severity = vuln.path(cvssKey).path("cvssData").path("baseSeverity");
            if (severity.isTextual()) {
                return severity.asText().toUpperCase();
            }
        }
        double score = vulnerabilityCvss(vuln);
        if (score >= 9.0) {
            return "CRITICAL";
        }
        if (score >= 7.0) {
            return "HIGH";
        }
        if (score >= 4.0) {
            return "MEDIUM";
        }
        if (score > 0) {
            return "LOW";
        }
        return "UNKNOWN";
    }

    private static double vulnerabilityCvss(JsonNode vuln) {
        for (String cvssKey : List.of("cvssV4", "cvssV3", "cvssV2")) {
            JsonNode scoreNode = vuln.path(cvssKey).path("cvssData").path("baseScore");
            if (scoreNode.isNumber()) {
                return scoreNode.asDouble();
            }
        }
        return 0.0;
    }

    private static boolean vulnerabilityHasFix(JsonNode vuln) {
        if (vuln.has("knownExploitedVulnerability")) {
            return true;
        }
        String description = vuln.path("description").asText("").toLowerCase();
        return description.contains("fixed in")
                || description.contains("upgrade to")
                || description.contains("update to")
                || description.contains("patched in")
                || description.contains("resolved in")
                || description.contains("remediation");
    }

    private static String packageConfidence(JsonNode dep) {
        Iterator<JsonNode> packages = dep.path("packages").elements();
        if (!packages.hasNext()) {
            return "LOW";
        }
        List<String> confidences = new ArrayList<>();
        packages.forEachRemaining(pkg -> confidences.add(pkg.path("confidence").asText("LOW").toUpperCase()));
        if (confidences.contains("HIGHEST") || confidences.contains("HIGH")) {
            return "HIGH";
        }
        if (confidences.contains("MEDIUM")) {
            return "MEDIUM";
        }
        return confidences.get(0);
    }

    private static Integer parseMajorVersion(String version) {
        if (version == null) {
            return null;
        }
        Matcher matcher = MAJOR_VERSION.matcher(version);
        if (!matcher.find()) {
            return null;
        }
        return Integer.parseInt(matcher.group(1));
    }

    private static Map<String, String> parseVersionUpdates(Path path) throws IOException {
        Map<String, String> latest = new HashMap<>();
        if (path == null || !Files.exists(path)) {
            return latest;
        }
        for (String line : Files.readAllLines(path)) {
            line = line.strip();
            Matcher matcher = VERSION_UPDATES.matcher(line);
            if (matcher.matches()) {
                latest.put(matcher.group(1).strip(), matcher.group(2).strip());
            }
        }
        return latest;
    }

    private static int majorVersionLag(String current, String latest) {
        Integer currentMajor = parseMajorVersion(current);
        Integer latestMajor = parseMajorVersion(latest);
        if (currentMajor == null || latestMajor == null) {
            return 0;
        }
        return Math.max(0, latestMajor - currentMajor);
    }

    private static Set<String> collectCveIds(JsonNode report) {
        Set<String> cves = new HashSet<>();
        for (JsonNode dep : report.path("dependencies")) {
            for (JsonNode vuln : dep.path("vulnerabilities")) {
                String name = vuln.path("name").asText("");
                if (CVE.matcher(name).matches()) {
                    cves.add(name.toUpperCase());
                }
            }
        }
        return cves;
    }

    private static Set<String> loadBaseline(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            return Set.of();
        }
        JsonNode data = MAPPER.readTree(path.toFile());
        Set<String> cves = new HashSet<>();
        for (JsonNode item : data.path("cves")) {
            cves.add(item.asText("").toUpperCase());
        }
        return cves;
    }
}
