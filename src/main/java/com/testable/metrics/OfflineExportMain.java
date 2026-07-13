package com.testable.metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Files;
import java.nio.file.Path;

public final class OfflineExportMain {

    public static void main(String[] args) throws Exception {
        Path root = Path.of("").toAbsolutePath();
        Path fixture = root.resolve("src/test/resources/fixtures/dependency-check_clean.json");
        Path platformDir = root.resolve("dependency_check/0");
        Path platformFile = platformDir.resolve("dependency_check.json");
        Files.createDirectories(platformDir);

        ScanReport report = MetricsReporter.computeMetrics(fixture, null, null);
        ObjectNode platformReport = PlatformJsonBuilder.buildPlatformJson(
                report,
                "src/test/resources/fixtures/dependency-check_clean.json"
        );
        new ObjectMapper().writerWithDefaultPrettyPrinter().writeValue(platformFile.toFile(), platformReport);
        System.out.println("Wrote " + platformFile);
    }
}
