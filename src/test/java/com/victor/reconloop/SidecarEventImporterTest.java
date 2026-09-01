package com.victor.reconloop;

import org.junit.Test;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class SidecarEventImporterTest {

    @Test
    public void importsValidInScopeRecordsAndQuarantinesBadOrUnsupportedLines() throws Exception {
        String input = """
                {"kind":"hostname","hostname":"api.example.test","tool":"subfinder"}
                {"kind":"payload","value":"<script>alert(1)</script>","tool":"payloads"}
                {"kind":"url","url":"https://outside.example.invalid/","tool":"katana"}
                not-json
                """;
        List<SidecarEvent.Event> accepted = new ArrayList<>();

        SidecarEventImporter.ImportResult result = SidecarEventImporter.importJsonl(new StringReader(input),
                event -> event.scopeCandidates().stream().anyMatch(url -> url.contains("example.test")), accepted::add);

        assertEquals(1, result.accepted());
        assertEquals(3, result.rejected());
        assertEquals(SidecarEvent.Kind.HOSTNAME, accepted.get(0).kind());
        assertTrue(result.rejectionReasons().stream().anyMatch(reason -> reason.contains("not importable")));
        assertTrue(result.rejectionReasons().stream().anyMatch(reason -> reason.contains("outside current Burp scope")));
    }

    @Test
    public void acceptsServiceWhenEitherScopedSchemeMatches() throws Exception {
        List<SidecarEvent.Event> accepted = new ArrayList<>();
        String input = "{\"kind\":\"service\",\"hostname\":\"api.example.test\",\"port\":8443,\"protocol\":\"tcp\",\"tool\":\"naabu\"}\n";

        SidecarEventImporter.ImportResult result = SidecarEventImporter.importJsonl(new StringReader(input),
                event -> event.scopeCandidates().contains("http://api.example.test:8443/"), accepted::add);

        assertEquals(1, result.accepted());
        assertEquals(0, result.rejected());
        assertEquals(List.of("https://api.example.test:8443/", "http://api.example.test:8443/"),
                accepted.get(0).scopeCandidates());
    }
}
