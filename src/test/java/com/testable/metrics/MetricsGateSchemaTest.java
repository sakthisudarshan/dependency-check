package com.testable.metrics;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MetricsGateSchemaTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void goldenFixturePassesRequire100() throws Exception {
        Path fixture = Path.of("src/test/resources/fixtures/platform_dependency_check_golden.json");
        List<String> errors = GateValidator.validate(fixture, true);
        assertTrue(errors.isEmpty(), String.join("\n", errors));
    }

    @Test
    void goldenFixtureHasEightClassifications() throws Exception {
        Path fixture = Path.of("src/test/resources/fixtures/platform_dependency_check_golden.json");
        Path classifications = Path.of("src/test/resources/fixtures/classifications.json");
        JsonNode data = MAPPER.readTree(fixture.toFile());
        JsonNode expected = MAPPER.readTree(classifications.toFile());

        assertEquals(8, data.path("metrics").size());
        for (int i = 0; i < expected.size(); i++) {
            assertEquals(
                    expected.get(i).asText(),
                    data.path("metrics").get(i).path("classification").asText()
            );
        }
        for (JsonNode metric : data.path("metrics")) {
            assertEquals(100, metric.path("value").asInt());
            assertEquals("PASS", metric.path("result").asText());
        }
    }

    @Test
    void fractionScoresFailValidation(@TempDir Path tempDir) throws Exception {
        Path fixture = Path.of("src/test/resources/fixtures/platform_dependency_check_golden.json");
        JsonNode bad = MAPPER.readTree(fixture.toFile());
        ((com.fasterxml.jackson.databind.node.ObjectNode) bad).put("HiddenRelationshipMapping", 0.88);
        ((com.fasterxml.jackson.databind.node.ObjectNode) bad.path("metrics").get(0)).put("value", 0.88);

        Path badFile = tempDir.resolve("bad.json");
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(badFile.toFile(), bad);

        List<String> errors = GateValidator.validate(badFile, true);
        assertFalse(errors.isEmpty());
    }

    @Test
    void computeMetricsFromCleanFixture() throws Exception {
        Path clean = Path.of("src/test/resources/fixtures/dependency-check_clean.json");
        ScanReport report = MetricsReporter.computeMetrics(clean, null, null);

        assertEquals(3, report.totalComponents());
        assertEquals(0, report.totalVulnerabilities());
        assertEquals(0, report.distinctCves());
        for (MetricResult metric : report.metrics()) {
            assertEquals(100.0, metric.normalisedScore());
            assertEquals("PASS", metric.result());
        }
    }

    @Test
    void offlineExportWritesPlatformFile(@TempDir Path tempDir) throws Exception {
        Path fixture = Path.of("src/test/resources/fixtures/dependency-check_clean.json");
        ScanReport report = MetricsReporter.computeMetrics(fixture, null, null);
        var platform = PlatformJsonBuilder.buildPlatformJson(
                report,
                "src/test/resources/fixtures/dependency-check_clean.json"
        );

        Path out = tempDir.resolve("dependency_check.json");
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(out.toFile(), platform);

        List<String> errors = GateValidator.validate(out, true);
        assertTrue(errors.isEmpty(), String.join("\n", errors));
        assertEquals("dependency_check", platform.path("tool").asText());
        assertEquals(100, platform.path("overall_score").asInt());
    }
}
