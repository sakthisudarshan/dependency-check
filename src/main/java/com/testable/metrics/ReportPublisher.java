package com.testable.metrics;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Set;
import java.util.TreeSet;

public final class ReportPublisher {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ReportPublisher() {
    }

    public static void publish(
            Path root,
            ScanReport report,
            String reportPath,
            Path baselinePath
    ) throws Exception {
        ObjectNode gateReport = PlatformJsonBuilder.buildGateReport(report);
        ObjectNode platformReport = PlatformJsonBuilder.buildPlatformJson(report, reportPath);

        Path platformDir = root.resolve("dependency_check/0");
        Path platformFile = platformDir.resolve("dependency_check.json");
        Files.createDirectories(platformDir);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(platformFile.toFile(), platformReport);

        Path reportsDir = root.resolve("reports");
        Files.createDirectories(reportsDir);
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(reportsDir.resolve("sca-gate.json").toFile(), gateReport);

        ObjectNode metricsReport = MAPPER.createObjectNode();
        metricsReport.put("generatedAt", Instant.now().toString());
        metricsReport.put("tool", report.tool());
        metricsReport.put("project", "com.testable:dependency-check-metrics-demo");
        metricsReport.put("totalComponents", report.totalComponents());
        metricsReport.put("totalVulnerabilities", report.totalVulnerabilities());
        metricsReport.put("distinctCves", report.distinctCves());
        metricsReport.put("overallScore", platformReport.path("overall_score").asInt());
        metricsReport.put("platformFile", MetricsConstants.PLATFORM_RELATIVE_PATH);
        metricsReport.put("s3Path", "s3://<bucket>/" + MetricsConstants.PLATFORM_RELATIVE_PATH);
        metricsReport.set("metrics", MAPPER.valueToTree(report.metrics()));
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(
                reportsDir.resolve("metrics-report.json").toFile(),
                metricsReport
        );

        Files.writeString(reportsDir.resolve("metrics-report.md"), renderTechnicalReport(report));
        Files.writeString(reportsDir.resolve("testable-sca-report.md"), renderDashboardReport(report, platformReport));

        writeBaseline(root, baselinePath, report);
    }

    private static void writeBaseline(Path root, Path baselinePath, ScanReport report) throws Exception {
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
        Path baseline = baselinePath == null ? root.resolve("baseline/cve_snapshot.json") : baselinePath;
        Files.createDirectories(baseline.getParent());
        MAPPER.writerWithDefaultPrettyPrinter().writeValue(baseline.toFile(), baselineNode);
    }

    static String renderTechnicalReport(ScanReport report) {
        StringBuilder builder = new StringBuilder();
        builder.append("# OWASP Dependency-Check SCA Metrics Report\n\n");
        builder.append("| Field | Value |\n");
        builder.append("| --- | --- |\n");
        builder.append("| Tool | ").append(report.tool()).append(" |\n");
        builder.append("| Components scanned | ").append(report.totalComponents()).append(" |\n");
        builder.append("| Vulnerability matches | ").append(report.totalVulnerabilities()).append(" |\n");
        builder.append("| Distinct CVEs | ").append(report.distinctCves()).append(" |\n");
        builder.append("| Gate status | ").append(report.allGatesPassed() ? "PASS" : "FAIL").append(" |\n\n");
        builder.append("| Metric (L4) | Technique (L3) | Score | Result | Threshold |\n");
        builder.append("| --- | --- | ---: | --- | --- |\n");
        for (MetricResult metric : report.metrics()) {
            builder.append("| ")
                    .append(metric.classification()).append(" | ")
                    .append(metric.technique()).append(" | ")
                    .append((int) Math.round(metric.normalisedScore())).append(" | ")
                    .append(metric.result()).append(" | ")
                    .append(metric.threshold()).append(" |\n");
        }
        builder.append('\n');
        return builder.toString();
    }

    static String renderDashboardReport(ScanReport report, ObjectNode platformReport) {
        StringBuilder builder = new StringBuilder();
        builder.append("# TESTABLE Dependency Risk (SCA) Gate Report\n\n");
        builder.append("## Gate Summary\n\n");
        builder.append("| Field | Value |\n");
        builder.append("| --- | --- |\n");
        builder.append("| Gate | ").append(MetricsConstants.GATE_NAME).append(" |\n");
        builder.append("| Tool | ").append(MetricsConstants.TOOL).append(" |\n");
        builder.append("| Execution Status | COMPLETED |\n");
        builder.append("| Overall Score | ").append(platformReport.path("overall_score").asInt()).append("/100 |\n");
        builder.append("| All Gates Passed | ").append(report.allGatesPassed()).append(" |\n");
        builder.append("| Platform File | `").append(MetricsConstants.PLATFORM_RELATIVE_PATH).append("` |\n");
        builder.append("| S3 Key | `").append(MetricsConstants.PLATFORM_RELATIVE_PATH).append("` |\n\n");

        builder.append("## Metrics (TESTABLE Dashboard Format)\n\n");
        builder.append("| CLASSIFICATION | VALUE | EXECUTION STATUS | RESULT | COVERAGE |\n");
        builder.append("| --- | ---: | --- | --- | ---: |\n");
        for (MetricResult metric : report.metrics()) {
            builder.append("| ")
                    .append(metric.technique()).append(" | ")
                    .append((int) Math.round(metric.normalisedScore())).append(" | ")
                    .append("COMPLETED | ")
                    .append(metric.result()).append(" | ")
                    .append((int) Math.round(metric.normalisedScore())).append(" |\n");
        }
        builder.append('\n');

        builder.append("## Score Keys\n\n");
        builder.append("| Technique | Metric | Platform Key | Score |\n");
        builder.append("| --- | --- | --- | ---: |\n");
        for (MetricResult metric : report.metrics()) {
            String key = MetricsConstants.METRIC_TO_PLATFORM_KEY.get(metric.classification());
            builder.append("| ")
                    .append(metric.technique()).append(" | ")
                    .append(metric.classification()).append(" | ")
                    .append(key).append(" | ")
                    .append((int) Math.round(metric.normalisedScore())).append(" |\n");
        }
        builder.append('\n');
        return builder.toString();
    }
}
