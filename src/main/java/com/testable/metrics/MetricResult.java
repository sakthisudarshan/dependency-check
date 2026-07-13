package com.testable.metrics;

import java.util.Map;

public record MetricResult(
        String classification,
        String technique,
        String metric,
        double rawValue,
        double normalisedScore,
        String threshold,
        String result,
        String derivation,
        String formula,
        Map<String, Object> details
) {
}
