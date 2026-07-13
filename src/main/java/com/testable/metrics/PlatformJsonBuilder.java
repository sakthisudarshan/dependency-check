package com.testable.metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.LinkedHashMap;
import java.util.Map;

public final class PlatformJsonBuilder {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PlatformJsonBuilder() {
    }

    public static ObjectNode buildGateReport(ScanReport report) {
        ObjectNode gate = MAPPER.createObjectNode();
        gate.put("gate_name", MetricsConstants.GATE_NAME);
        gate.put("tool", report.tool());
        gate.put("execution_status", "COMPLETED");
        gate.put("total_components", report.totalComponents());
        gate.put("total_vulnerabilities", report.totalVulnerabilities());
        gate.put("distinct_cves", report.distinctCves());
        gate.put("all_gates_passed", report.allGatesPassed());

        ArrayNode metrics = gate.putArray("metrics");
        for (MetricResult metric : report.metrics()) {
            ObjectNode entry = metrics.addObject();
            entry.put("classification", metric.classification());
            entry.put("technique", metric.technique());
            entry.put("value", metric.normalisedScore());
            entry.put("raw_value", metric.rawValue());
            entry.put("result", metric.result());
            entry.put("coverage", metric.normalisedScore());
            entry.put("execution_status", "COMPLETED");
            entry.put("threshold", metric.threshold());
            entry.put("derivation", metric.derivation());
            entry.put("formula", metric.formula());
            entry.set("details", MAPPER.valueToTree(metric.details()));
        }
        return gate;
    }

    public static ObjectNode buildPlatformJson(ScanReport report, String reportPath) {
        Map<String, Integer> platformScores = new LinkedHashMap<>();
        for (MetricResult metric : report.metrics()) {
            String camel = MetricsConstants.METRIC_TO_PLATFORM_KEY.get(metric.classification());
            String metricSnake = MetricsConstants.metricSnakeKey(metric.classification());
            String techniqueSnake = MetricsConstants.techniqueSnakeKey(metric.technique());
            int score = (int) Math.round(metric.normalisedScore());
            platformScores.put(camel, score);
            platformScores.put(metricSnake, score);
            platformScores.put(techniqueSnake, score);
        }

        int overallScore = MetricsConstants.PLATFORM_SCORE_KEYS.stream()
                .mapToInt(key -> platformScores.getOrDefault(key, 0))
                .min()
                .orElse(0);

        ObjectNode platform = MAPPER.createObjectNode();
        platform.put("exit", report.allGatesPassed() ? 0 : 1);
        platform.put("scan_ok", true);
        platform.put("report_path", reportPath);
        platform.put("platform_file", MetricsConstants.PLATFORM_RELATIVE_PATH);
        platform.put("total_components", report.totalComponents());
        platform.put("total_vulnerabilities", report.totalVulnerabilities());
        platform.put("distinct_cves", report.distinctCves());
        platform.put("totalComponents", report.totalComponents());
        platform.put("totalVulnerabilities", report.totalVulnerabilities());
        platform.put("distinctCves", report.distinctCves());
        platform.put("overall_score", overallScore);
        platform.put("gate_name", MetricsConstants.GATE_NAME);
        platform.put("tool", MetricsConstants.TOOL);
        platform.put("execution_status", "COMPLETED");
        platform.put("all_gates_passed", report.allGatesPassed());
        platform.put("scoring_policy", "Excel normalisation formulas from Dependency-Check JSON report");
        platform.put("scoringPolicy", "Excel normalisation formulas from Dependency-Check JSON report");

        platformScores.forEach(platform::put);
        for (String key : MetricsConstants.PLATFORM_SCORE_KEYS) {
            platform.put(key, platformScores.getOrDefault(key, 0));
        }

        ArrayNode metrics = platform.putArray("metrics");
        for (MetricResult metric : report.metrics()) {
            ObjectNode entry = metrics.addObject();
            entry.put("classification", metric.technique());
            entry.put("metric", metric.classification());
            entry.put("technique", metric.technique());
            entry.put("value", (int) Math.round(metric.normalisedScore()));
            entry.put("execution_status", "COMPLETED");
            entry.put("result", metric.result());
            entry.put("coverage", (int) Math.round(metric.normalisedScore()));
        }
        return platform;
    }
}
