package com.testable.demo;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Minimal demo application for OWASP Dependency-Check SCA validation.
 * Uses only maintained, permissively licensed dependencies at current stable versions.
 */
public final class App {

    private static final Logger LOG = LoggerFactory.getLogger(App.class);

    private App() {
    }

    public static String greet(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("name must not be blank");
        }
        String message = "Hello, " + name.trim();
        LOG.info(message);
        return message;
    }

    public static void main(String[] args) {
        String target = args.length > 0 ? args[0] : "TESTABLE";
        System.out.println(greet(target));
    }
}
