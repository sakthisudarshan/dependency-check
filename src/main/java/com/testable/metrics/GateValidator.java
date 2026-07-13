package com.testable.metrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public final class GateValidator {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private GateValidator() {
    }

    public static List<String> validate(Path platformFile, boolean requirePerfect) throws IOException {
        List<String> errors = new ArrayList<>();
        if (!Files.exists(platformFile)) {
            errors.add("platform file not found: " + platformFile);
            return errors;
        }

        JsonNode data = MAPPER.readTree(platformFile.toFile());
        if (data.path("exit").asInt(-1) != 0) {
            errors.add("exit must be 0, got " + data.path("exit"));
        }
        if (!data.path("scan_ok").asBoolean(false)) {
            errors.add("scan_ok must be true");
        }

        int totalVulns = data.path("total_vulnerabilities").asInt(-1);
        int distinctCves = data.path("distinct_cves").asInt(-1);
        if (requirePerfect && totalVulns != 0) {
            errors.add("total_vulnerabilities must be 0 for 100/100 demo, got " + totalVulns);
        }
        if (requirePerfect && distinctCves != 0) {
            errors.add("distinct_cves must be 0 for 100/100 demo, got " + distinctCves);
        }

        for (String key : MetricsConstants.PLATFORM_SCORE_KEYS) {
            if (!data.has(key)) {
                errors.add("missing platform score key: " + key);
                continue;
            }
            JsonNode value = data.get(key);
            if (!value.isNumber()) {
                errors.add(key + " must be numeric");
                continue;
            }
            double numeric = value.asDouble();
            if (numeric <= 1.0) {
                errors.add(key + "=" + numeric + " looks like a 0-1 fraction; TESTABLE expects 0-100 scale");
            }
            if (requirePerfect && numeric < 100) {
                errors.add(key + "=" + numeric + " below required minimum 100");
            }
        }

        JsonNode metrics = data.path("metrics");
        if (!metrics.isArray()) {
            errors.add("metrics array missing from platform JSON");
            return errors;
        }

        for (String classification : MetricsConstants.CLASSIFICATIONS) {
            JsonNode metric = findMetric(metrics, classification);
            if (metric == null) {
                errors.add("missing classification in metrics[]: " + classification);
                continue;
            }
            JsonNode value = metric.path("value");
            JsonNode coverage = metric.path("coverage");
            String result = metric.path("result").asText("");
            if (!"PASS".equals(result)) {
                errors.add(classification + ": result must be PASS, got " + result);
            }
            if (requirePerfect) {
                if (!value.isNumber() || value.asDouble() < 100) {
                    errors.add(classification + ": value=" + value + " below 100");
                }
                if (!coverage.isNumber() || coverage.asDouble() < 100) {
                    errors.add(classification + ": coverage=" + coverage + " below 100");
                }
            } else {
                if (!value.isNumber()) {
                    errors.add(classification + ": value must be numeric");
                }
                if (!coverage.isNumber()) {
                    errors.add(classification + ": coverage must be numeric");
                }
            }
        }
        return errors;
    }

    private static JsonNode findMetric(JsonNode metrics, String classification) {
        for (JsonNode metric : metrics) {
            if (classification.equals(metric.path("classification").asText())) {
                return metric;
            }
        }
        return null;
    }
}
