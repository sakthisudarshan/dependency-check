package com.testable.metrics;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class MetricsConstants {

    public static final String GATE_NAME = "OWASP Dependency-Check SCA Gate";
    public static final String TOOL = "dependency_check";
    public static final String PLATFORM_RELATIVE_PATH = "dependency_check/0/dependency_check.json";

    public static final List<String> CLASSIFICATIONS = List.of(
            "Hidden Relationship Mapping",
            "Legal Risk Validation",
            "Trust Integrity Verification",
            "Community Vitality Tracking",
            "Mitigation Effort Ranking",
            "Real-Time Alerting",
            "Known CVE Count",
            "Version Lag Assessment"
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

    public static final Map<String, String> CLASSIFICATION_TO_PLATFORM_KEY = buildClassificationMap();

    private MetricsConstants() {
    }

    private static Map<String, String> buildClassificationMap() {
        Map<String, String> map = new LinkedHashMap<>();
        for (int i = 0; i < CLASSIFICATIONS.size(); i++) {
            map.put(CLASSIFICATIONS.get(i), PLATFORM_SCORE_KEYS.get(i));
        }
        return Map.copyOf(map);
    }

    public static String snakeKey(String classification) {
        return switch (classification) {
            case "Hidden Relationship Mapping" -> "hidden_relationship_mapping";
            case "Legal Risk Validation" -> "legal_risk_validation";
            case "Trust Integrity Verification" -> "trust_integrity_verification";
            case "Community Vitality Tracking" -> "community_vitality_tracking";
            case "Mitigation Effort Ranking" -> "mitigation_effort_ranking";
            case "Real-Time Alerting" -> "real_time_alerting";
            case "Known CVE Count" -> "known_cve_count";
            case "Version Lag Assessment" -> "version_lag_assessment";
            default -> classification.toLowerCase().replace(' ', '_');
        };
    }
}
