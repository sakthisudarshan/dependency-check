package com.testable.metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.StreamSupport;

public final class PlatformExporter {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static void main(String[] args) throws IOException {
        boolean failOnGate = List.of(args).contains("--fail-on-gate");
        Path root = Path.of("").toAbsolutePath();

        Path reportPath = findReport(root);
        Path versionUpdates = root.resolve("target/dependency-updates.txt");
        Path baseline = root.resolve("baseline/cve_snapshot.json");
        Path platformDir = root.resolve("dependency_check/0");
        Path platformFile = platformDir.resolve("dependency_check.json");
        Files.createDirectories(platformDir);

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

        ObjectNode gateReport = PlatformJsonBuilder.buildGateReport(report);
        String relativeReportPath = root.relativize(reportPath).toString().replace('\\', '/');
        ObjectNode platformReport = PlatformJsonBuilder.buildPlatformJson(report, relativeReportPath);

        Path reportsDir = root.resolve("reports");
        Files.createDirectories(reportsDir);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(reportsDir.resolve("sca-gate.json").toFile(), gateReport);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(platformFile.toFile(), platformReport);

        ObjectNode metricsReport = MAPPER.createObjectNode();
        metricsReport.put("generatedAt", Instant.now().toString());
        metricsReport.put("tool", report.tool());
        metricsReport.put("totalComponents", report.totalComponents());
        metricsReport.put("totalVulnerabilities", report.totalVulnerabilities());
        metricsReport.put("distinctCves", report.distinctCves());
        metricsReport.put("overallScore", platformReport.path("overall_score").asInt());
        metricsReport.put("platformFile", MetricsConstants.PLATFORM_RELATIVE_PATH);
        metricsReport.set("metrics", MAPPER.valueToTree(report.metrics()));
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(reportsDir.resolve("metrics-report.json").toFile(), metricsReport);
        Files.writeString(reportsDir.resolve("metrics-report.md"), renderMarkdown(report));

        Set<String> cves = new TreeSet<>();
        for (var dep : report.dependencies()) {
            for (var vuln : dep.path("vulnerabilities")) {
                String name = vuln.path("name").asText("");
                if (name.startsWith("CVE-")) {
                    cves.add(name.toUpperCase());
                }
            }
        }
        ObjectNode baselineNode = MAPPER.createObjectNode();
        ArrayNode cveArray = baselineNode.putArray("cves");
        cves.forEach(cveArray::add);
        baselineNode.put("updatedAt", Instant.now().toString());
        Files.createDirectories(baseline.getParent());
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(baseline.toFile(), baselineNode);

        System.out.println("Wrote platform gate: " + platformFile);
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

    private static String renderMarkdown(ScanReport report) {
        StringBuilder builder = new StringBuilder();
        builder.append("# OWASP Dependency-Check SCA Metrics Report\n\n");
        builder.append("- Tool: **").append(report.tool()).append("**\n");
        builder.append("- Components scanned: **").append(report.totalComponents()).append("**\n");
        builder.append("- Vulnerability matches: **").append(report.totalVulnerabilities()).append("**\n");
        builder.append("- Distinct CVEs: **").append(report.distinctCves()).append("**\n\n");
        builder.append("| Classification | Technique | Score | Result | Threshold |\n");
        builder.append("| --- | --- | ---: | --- | --- |\n");
        for (MetricResult metric : report.metrics()) {
            builder.append("| ")
                    .append(metric.classification()).append(" | ")
                    .append(metric.technique()).append(" | ")
                    .append(String.format("%.2f", metric.normalisedScore())).append(" | ")
                    .append(metric.result()).append(" | ")
                    .append(metric.threshold()).append(" |\n");
        }
        builder.append('\n');
        return builder.toString();
    }
}
