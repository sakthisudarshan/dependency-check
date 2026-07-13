package com.testable.metrics;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class MetricsConstants {

    public static final String GATE_NAME = "OWASP Dependency-Check SCA Gate";
    public static final String TOOL = "dependency_check";
    public static final String PLATFORM_RELATIVE_PATH = "dependency_check/0/dependency_check.json";

    /** L4 metric names used for score keys and internal computation. */
    public static final List<String> METRICS = List.of(
            "Hidden Relationship Mapping",
            "Legal Risk Validation",
            "Trust Integrity Verification",
            "Community Vitality Tracking",
            "Mitigation Effort Ranking",
            "Real-Time Alerting",
            "Known CVE Count",
            "Version Lag Assessment"
    );

    /**
     * L3 technique names — TESTABLE dashboard CLASSIFICATION column expects these
     * in metrics[].classification.
     */
    public static final List<String> TECHNIQUES = List.of(
            "Transitive Dependency Analysis",
            "License Compliance Testing",
            "Supply Chain Security Analysis",
            "Dependency Health Monitoring",
            "Risk Prioritization",
            "Continuous Dependency Monitoring",
            "Vulnerability Dependency Detection",
            "Outdated Dependency Detection"
    );

    public static final List<String> PLATFORM_SCORE_KEYS = List.of(
            "HiddenRelationshipMapping",
            "LegalRiskValidation",
            "TrustIntegrityVerification",
            "CommunityVitalityTracking",
            "MitigationEffortRanking",
            "RealTimeAlerting",
            "KnownCVECount",
            "VersionLagAssessment"
    );

    public static final Map<String, String> METRIC_TO_PLATFORM_KEY = buildMetricMap();
    public static final Map<String, String> TECHNIQUE_TO_METRIC = buildTechniqueMap();

    private MetricsConstants() {
    }

    private static Map<String, String> buildMetricMap() {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < METRICS.size(); i++) {
            map.put(METRICS.get(i), PLATFORM_SCORE_KEYS.get(i));
        }
        return Map.copyOf(map);
    }

    private static Map<String, String> buildTechniqueMap() {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < TECHNIQUES.size(); i++) {
            map.put(TECHNIQUES.get(i), METRICS.get(i));
        }
        return Map.copyOf(map);
    }

    public static String metricSnakeKey(String metric) {
        return switch (metric) {
            case "Hidden Relationship Mapping" -> "hidden_relationship_mapping";
            case "Legal Risk Validation" -> "legal_risk_validation";
            case "Trust Integrity Verification" -> "trust_integrity_verification";
            case "Community Vitality Tracking" -> "community_vitality_tracking";
            case "Mitigation Effort Ranking" -> "mitigation_effort_ranking";
            case "Real-Time Alerting" -> "real_time_alerting";
            case "Known CVE Count" -> "known_cve_count";
            case "Version Lag Assessment" -> "version_lag_assessment";
            default -> metric.toLowerCase().replace(' ', '_');
        };
    }

    public static String techniqueSnakeKey(String technique) {
        return switch (technique) {
            case "Transitive Dependency Analysis" -> "transitive_dependency_analysis";
            case "License Compliance Testing" -> "license_compliance_testing";
            case "Supply Chain Security Analysis" -> "supply_chain_security_analysis";
            case "Dependency Health Monitoring" -> "dependency_health_monitoring";
            case "Risk Prioritization" -> "risk_prioritization";
            case "Continuous Dependency Monitoring" -> "continuous_dependency_monitoring";
            case "Vulnerability Dependency Detection" -> "vulnerability_dependency_detection";
            case "Outdated Dependency Detection" -> "outdated_dependency_detection";
            default -> technique.toLowerCase().replace(' ', '_');
        };
    }
}
