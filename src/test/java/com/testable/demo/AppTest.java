package com.testable.demo;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AppTest {

    @Test
    void greetReturnsPersonalizedMessage() {
        assertEquals("Hello, TESTABLE", App.greet("TESTABLE"));
    }

    @Test
    void greetRejectsBlankName() {
        assertThrows(IllegalArgumentException.class, () -> App.greet("  "));
    }
}
