package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class SidecarEventTest {

    @Test
    public void parsesCanonicalResolvedHostAndBuildsScopeCandidates() {
        SidecarEvent.Event event = SidecarEvent.parse("""
                {"kind":"resolved_host","hostname":"api.example.test","addresses":["203.0.113.10"],
                 "cnames":[],"tool":"dnsx","source":"dnsx","run_id":"run-42"}
                """);

        assertEquals(SidecarEvent.Kind.RESOLVED_HOST, event.kind());
        assertEquals("api.example.test", event.hostname());
        assertEquals(List.of("203.0.113.10"), event.addresses());
        assertEquals(List.of("https://api.example.test/", "http://api.example.test/"), event.scopeCandidates());
        assertTrue(event.materializable());
    }

    @Test
    public void parsesFindingOnlyWhenItsTargetIsAnHttpUrl() {
        SidecarEvent.Event finding = SidecarEvent.parse("""
                {"kind":"finding","value":"https://api.example.test/v1?q=x","tool":"nuclei",
                 "severity":"high","evidence":"matched template"}
                """);

        assertEquals(SidecarEvent.Kind.FINDING, finding.kind());
        assertEquals("https://api.example.test/v1?q=x", finding.url());
        assertEquals("high", finding.severity());
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsUnknownOrUncontractedKinds() {
        SidecarEvent.parse("{\"kind\":\"js_files\",\"value\":\"https://api.example.test/app.js\"}");
    }

    @Test(expected = IllegalArgumentException.class)
    public void rejectsFindingWithoutHttpTarget() {
        SidecarEvent.parse("{\"kind\":\"finding\",\"value\":\"api.example.test:443\",\"tool\":\"nuclei\"}");
    }
}
