package com.victor.reconloop.contracts;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class ScopeTest {

    @Test
    public void apexIncludeCoversChildren() {
        Scope scope = Scope.of("p", List.of("example.com"));
        assertTrue(scope.allowsHost("example.com"));
        assertTrue(scope.allowsHost("API.Example.COM"));
        assertTrue(scope.allowsHost("a.b.example.com"));
        assertFalse(scope.allowsHost("example.com.evil.test"));
        assertFalse(scope.allowsHost("notexample.com"));
    }

    @Test
    public void wildcardIncludeExcludesApex() {
        Scope scope = Scope.of("p", List.of("*.example.com"));
        assertFalse(scope.allowsHost("example.com"));
        assertTrue(scope.allowsHost("www.example.com"));
    }

    @Test
    public void excludeWins() {
        Scope scope = Scope.of("p", List.of("example.com"), List.of("admin.example.com"));
        assertTrue(scope.allowsHost("www.example.com"));
        assertFalse(scope.allowsHost("admin.example.com"));
        assertFalse(scope.allowsHost("x.admin.example.com"));
    }

    @Test
    public void emptyIncludeFailsClosed() {
        Scope scope = Scope.of("p", List.of());
        assertTrue(scope.isEmpty());
        assertFalse(scope.allowsHost("example.com"));
    }
}
