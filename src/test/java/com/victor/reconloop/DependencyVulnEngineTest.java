package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class DependencyVulnEngineTest {

    private final DependencyVulnEngine engine = new DependencyVulnEngine();

    @Test
    public void compareVersionsOrdersNumerically() {
        assertEquals(0, DependencyVulnEngine.compareVersions("1.2.0", "1.2.0"));
        assertTrue(DependencyVulnEngine.compareVersions("1.2.0", "1.3.0") < 0);
        assertTrue(DependencyVulnEngine.compareVersions("2.0.0", "1.9.9") > 0);
        // Missing trailing segments are treated as zero, not as a string-compare mismatch.
        assertEquals(0, DependencyVulnEngine.compareVersions("1.2", "1.2.0"));
        assertTrue(DependencyVulnEngine.compareVersions("1.10.0", "1.9.0") > 0);
    }

    @Test
    public void isVulnerableSentinelAlwaysFlags() {
        assertTrue(DependencyVulnEngine.isVulnerable("999.0.0", "99999"));
    }

    @Test
    public void isVulnerableComparesAgainstFixedVersion() {
        assertTrue(DependencyVulnEngine.isVulnerable("4.17.20", "4.17.21"));
        assertFalse(DependencyVulnEngine.isVulnerable("4.17.21", "4.17.21"));
        assertFalse(DependencyVulnEngine.isVulnerable("4.18.0", "4.17.21"));
    }

    @Test
    public void scanFlagsVulnerableJQueryVersionFromUrl() {
        List<DependencyVulnEngine.LibIssue> issues = engine.scan("https://cdn.example.com/js/jquery-3.4.0.min.js", "");

        DependencyVulnEngine.LibIssue jquery = issues.stream()
                .filter(i -> i.library().equals("jQuery")).findFirst().orElse(null);
        assertNotNull(jquery);
        assertEquals("3.4.0", jquery.version());
    }

    @Test
    public void scanDoesNotFlagPatchedJQueryVersion() {
        List<DependencyVulnEngine.LibIssue> issues = engine.scan("https://cdn.example.com/js/jquery-3.7.1.min.js", "");

        assertFalse(issues.stream().anyMatch(i -> i.library().equals("jQuery")));
    }

    @Test
    public void scanFlagsEndOfLifeAngularJsRegardlessOfVersion() {
        List<DependencyVulnEngine.LibIssue> issues =
                engine.scan("https://cdn.example.com/libs/angular-1.8.2/angular.js", "");

        assertTrue(issues.stream().anyMatch(i -> i.library().equals("AngularJS") && i.version().equals("1.8.2")));
    }

    @Test
    public void scanIgnoresBlankInput() {
        assertTrue(engine.scan(null, null).isEmpty());
        assertTrue(engine.scan("", "").isEmpty());
    }
}
