package com.victor.reconloop;

import org.junit.Test;

import java.net.URI;

import static org.junit.Assert.*;

public class InterestingResourceCatalogTest {

    // ---- pre-existing interesting()/classify() ----

    @Test
    public void knownBasenameIsInteresting() {
        assertTrue(InterestingResourceCatalog.interesting(URI.create("https://a.example/.env")));
        assertTrue(InterestingResourceCatalog.interesting(URI.create("https://a.example/config/package.json")));
    }

    @Test
    public void knownExtensionIsInteresting() {
        assertTrue(InterestingResourceCatalog.interesting(URI.create("https://a.example/app.js.bak")));
        assertTrue(InterestingResourceCatalog.interesting(URI.create("https://a.example/dump.sql")));
    }

    @Test
    public void ordinaryPageIsNotInteresting() {
        assertFalse(InterestingResourceCatalog.interesting(URI.create("https://a.example/about-us")));
        assertFalse(InterestingResourceCatalog.interesting(URI.create("https://a.example/products/123")));
    }

    @Test
    public void classifyDistinguishesDirectoryFileAndEndpoint() {
        assertEquals("directory", InterestingResourceCatalog.classify(URI.create("https://a.example/uploads/")));
        assertEquals("file:.env", InterestingResourceCatalog.classify(URI.create("https://a.example/config.env")));
        assertEquals("endpoint", InterestingResourceCatalog.classify(URI.create("https://a.example/users/123")));
        assertEquals("interesting-file", InterestingResourceCatalog.classify(URI.create("https://a.example/dockerfile")));
    }

    // ---- debug/ops tool paths ----

    @Test
    public void springActuatorPathsAreDebugTools() {
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/actuator/env")));
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/actuator/heapdump")));
    }

    @Test
    public void phpinfoAndGitExposureAreDebugTools() {
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/phpinfo.php")));
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/.git/HEAD")));
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/.git/config")));
    }

    @Test
    public void adminerAndPhpMyAdminAreDebugTools() {
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/adminer.php")));
        assertTrue(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/phpmyadmin/index.php")));
    }

    @Test
    public void ordinaryPathIsNotADebugTool() {
        assertFalse(InterestingResourceCatalog.looksLikeDebugTool(URI.create("https://a.example/products/123/reviews")));
    }

    @Test
    public void nullOrPathlessUriIsSafeForDebugToolCheck() {
        assertFalse(InterestingResourceCatalog.looksLikeDebugTool(null));
    }

    // ---- BFLA path candidates ----

    @Test
    public void adminSegmentIsAPrivilegedPathCandidate() {
        assertTrue(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/admin/users")));
        assertTrue(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/api/v1/admin/settings")));
    }

    @Test
    public void internalBackendManageConsoleSegmentsAreCandidates() {
        assertTrue(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/internal/status")));
        assertTrue(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/backend/jobs")));
        assertTrue(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/manage/reports")));
        assertTrue(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/console/logs")));
    }

    @Test
    public void substringMatchWithinAnUnrelatedSegmentIsNotFlagged() {
        // Segment-based matching: "administered" and "consolewhat" must not match "admin"/"console"
        // as a bare substring, unlike the debug-tool check which intentionally does substring-match.
        assertFalse(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/administered-by/us")));
        assertFalse(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/consolewhatever/x")));
    }

    @Test
    public void ordinaryPathIsNotAPrivilegedPathCandidate() {
        assertFalse(InterestingResourceCatalog.looksLikePrivilegedPath(URI.create("https://a.example/products/123")));
    }

    @Test
    public void nullOrPathlessUriIsSafeForPrivilegedPathCheck() {
        assertFalse(InterestingResourceCatalog.looksLikePrivilegedPath(null));
    }
}
