package com.testable.metrics;

import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class PlatformExporter {

    public static void main(String[] args) throws Exception {
        boolean failOnGate = List.of(args).contains("--fail-on-gate");
        Path root = Path.of("").toAbsolutePath();

        Path reportPath = findReport(root);
        Path versionUpdates = root.resolve("target/dependency-updates.txt");
        Path baseline = root.resolve("baseline/cve_snapshot.json");

        if (reportPath == null) {
            System.err.println("Missing Dependency-Check JSON report under target/");
            System.err.println("Run: mvnw clean test dependency-check:check");
            System.exit(2);
        }

        ScanReport report = MetricsReporter.computeMetrics(
                reportPath,
                Files.exists(versionUpdates) ? versionUpdates : null,
                Files.exists(baseline) ? baseline : null
        );

        String relativeReportPath = root.relativize(reportPath).toString().replace('\\', '/');
        ReportPublisher.publish(root, report, relativeReportPath, baseline);

        System.out.println("Wrote platform gate: " + root.resolve("dependency_check/0/dependency_check.json"));
        System.out.println("S3 target path: s3://<bucket>/" + MetricsConstants.PLATFORM_RELATIVE_PATH);

        if (failOnGate && !report.allGatesPassed()) {
            System.err.println("SCA gate FAILED");
            System.exit(1);
        }
    }

    private static Path findReport(Path root) {
        List<Path> candidates = List.of(
                root.resolve("target/dependency-check/dependency-check-report.json"),
                root.resolve("target/dependency-check-report.json")
        );
        for (Path candidate : candidates) {
            if (Files.exists(candidate)) {
                return candidate;
            }
        }
        return null;
    }
}
