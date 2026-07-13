package com.testable.metrics;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public final class ValidateGateMain {

    public static void main(String[] args) throws IOException {
        boolean requirePerfect = List.of(args).contains("--require-100");
        Path platformFile = Path.of("dependency_check/0/dependency_check.json");

        for (int i = 0; i < args.length - 1; i++) {
            if ("--file".equals(args[i])) {
                platformFile = Path.of(args[i + 1]);
            }
        }

        if (!Files.exists(platformFile)) {
            System.err.println("FAIL: platform file not found: " + platformFile.toAbsolutePath());
            System.err.println("Run: mvn -Ptestable-export exec:java@export-platform");
            System.exit(2);
        }

        List<String> errors = GateValidator.validate(platformFile, requirePerfect);
        if (!errors.isEmpty()) {
            System.out.println("METRICS GATE VALIDATION: FAIL");
            errors.forEach(error -> System.out.println("  - " + error));
            System.exit(1);
        }

        String mode = requirePerfect ? "100/100" : "Excel gate thresholds";
        System.out.println("METRICS GATE VALIDATION: PASS (" + mode + ")");
        System.out.println("  File: " + platformFile.toAbsolutePath());
        System.out.println("  Classifications: " + MetricsConstants.CLASSIFICATIONS.size() + "/8 PASS");
    }
}
