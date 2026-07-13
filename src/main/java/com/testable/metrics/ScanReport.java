package com.testable.metrics;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;

public record ScanReport(
        String tool,
        String reportPath,
        int totalComponents,
        int totalVulnerabilities,
        int distinctCves,
        List<MetricResult> metrics,
        List<JsonNode> dependencies
) {
    public boolean allGatesPassed() {
        return metrics.stream().allMatch(metric -> "PASS".equals(metric.result()));
    }
}
