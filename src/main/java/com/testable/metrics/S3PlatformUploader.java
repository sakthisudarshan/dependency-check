package com.testable.metrics;

import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;

import java.nio.file.Files;
import java.nio.file.Path;

public final class S3PlatformUploader {

    public static void main(String[] args) throws Exception {
        Path platformFile = Path.of("dependency_check/0/dependency_check.json");
        String bucket = System.getenv("TESTABLE_METRICS_BUCKET");
        String region = System.getenv().getOrDefault("AWS_DEFAULT_REGION", "us-east-1");

        if (!Files.exists(platformFile)) {
            throw new IllegalStateException("Platform file not found: " + platformFile);
        }
        if (bucket == null || bucket.isBlank()) {
            throw new IllegalStateException("Set TESTABLE_METRICS_BUCKET to the target S3 bucket name.");
        }

        String key = MetricsConstants.PLATFORM_RELATIVE_PATH;
        try (S3Client s3 = S3Client.builder()
                .region(Region.of(region))
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build()) {
            s3.putObject(
                    PutObjectRequest.builder()
                            .bucket(bucket)
                            .key(key)
                            .contentType("application/json")
                            .build(),
                    RequestBody.fromFile(platformFile)
            );
        }

        System.out.println("Uploaded " + platformFile + " to s3://" + bucket + "/" + key);
    }
}
