package com.victor.reconloop;

import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;
import static com.victor.reconloop.EvidenceAgentTools.Tool.*;

public class EvidenceAgentToolsTest {
    private static final Set<EvidenceAgentTools.Tool> ALL = EnumSet.allOf(EvidenceAgentTools.Tool.class);
    static AiAnalysis.Snapshot snapshot(String text) { return AiAnalysis.prepare(List.of(AiAnalysisTest.source(text)), ""); }
    private static String tool(AiAnalysis.Snapshot snapshot, String name, Map<String, Object> args) { return EvidenceAgentTools.execute(snapshot, ALL, name, args); }

    @Test public void indexReadAndEvidenceCheckUseOnlyTheSelectedSnapshot() {
        var snapshot = snapshot("innerHTML = location.hash;");
        assertTrue(tool(snapshot, "source_index", Map.of()).contains(AiAnalysis.sha256(snapshot.sources().getFirst().text())));
        assertTrue(tool(snapshot, "read_source", Map.of("source_id", "s1", "start", 0, "length", 9)).contains("innerHTML"));
        assertTrue(tool(snapshot, "check_evidence", Map.of("source_id", "s1", "quote", "innerHTML")).contains("verbatim_present=true"));
        assertTrue(tool(snapshot, "check_evidence", Map.of("source_id", "s1", "quote", "fabricated")).contains("verbatim_present=false"));
    }

    @Test public void literalSearchHandlesRegexMetacharactersAndUnicodeOffsets() {
        var snapshot = snapshot("İ\nconst RX = 'a.*b';\nINNERHTML");
        assertTrue(tool(snapshot, "search_sources", Map.of("query", "a.*b")).contains("a.*b"));
        assertTrue(tool(snapshot, "search_sources", Map.of("query", "innerhtml")).contains("INNERHTML"));
        assertTrue(tool(snapshot, "search_sources", Map.of("query", ".*")).contains("a.*b"));
        assertFalse(tool(snapshot, "search_sources", Map.of("query", "z.*q")).contains("@"));
    }

    @Test public void compareReportsCapturedDifferencesWithoutClaimingAnAuthorizationBug() {
        var snapshot = AiAnalysis.prepare(List.of(AiAnalysisTest.source("HTTP 200\nuser=one"),
                new AiAnalysis.Source("s2", AiAnalysis.Kind.HTTP_EXCHANGE, "other", "HTTP 200\nuser=two")), "");
        String result = tool(snapshot, "compare_sources", Map.of("left", "s1", "right", "s2"));
        assertTrue(result.contains("First difference")); assertTrue(result.contains("no behavioral or authorization conclusion"));
        assertTrue(tool(snapshot, "compare_sources", Map.of("left", "s1", "right", "s1")).contains("Identical"));
    }

    @Test public void decodeRequiresASourceExcerptAndRedactsTheDerivedTextAgain() {
        String encoded = Base64.getEncoder().encodeToString("api_key=DO-NOT-FORWARD".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        var snapshot = snapshot("const encoded='" + encoded + "';");
        String result = tool(snapshot, "decode_excerpt", Map.of("source_id", "s1", "text", encoded, "encoding", "base64"));
        assertFalse(result.contains("DO-NOT-FORWARD")); assertTrue(result.contains("api_key=[REDACTED]"));
        assertThrows(IllegalArgumentException.class, () -> tool(snapshot, "decode_excerpt", Map.of("source_id", "s1", "text", "YQ==", "encoding", "base64")));
    }

    @Test public void urlDecodePreservesLiteralPlusAndNeverEvaluatesText() {
        String result = tool(snapshot("%3Cscript%3E+marker"), "decode_excerpt", Map.of("source_id", "s1", "text", "%3Cscript%3E+marker", "encoding", "url"));
        assertTrue(result.contains("<script>+marker")); assertTrue(result.contains("not executed"));
    }

    @Test public void unknownForbiddenAndAmbientIoToolsAreUnavailable() {
        var snapshot = snapshot("selected text");
        for (String name : List.of("fetch_url", "send_request", "shell", "read_file", "run_poc", "READ_SOURCE"))
            assertThrows(name, IllegalArgumentException.class, () -> tool(snapshot, name, Map.of()));
        assertThrows(IllegalArgumentException.class, () -> EvidenceAgentTools.execute(snapshot, Set.of(SOURCE_INDEX), "read_source",
                Map.of("source_id", "s1", "start", 0, "length", 3)));
        assertThrows(IllegalArgumentException.class, () -> tool(snapshot, "source_index", Map.of("path", "/etc/passwd")));
    }

    @Test public void wrongSourcesRangesAndTypesAreRejected() {
        var snapshot = snapshot("selected text");
        for (Map<String, Object> args : List.<Map<String, Object>>of(
                Map.of("source_id", "s9", "start", 0, "length", 3), Map.of("source_id", "s1", "start", -1, "length", 3),
                Map.of("source_id", "s1", "start", 0.5, "length", 3), Map.of("source_id", "s1", "start", "0", "length", 3),
                Map.of("source_id", "s1", "start", 0, "length", 3001)))
            assertThrows(IllegalArgumentException.class, () -> tool(snapshot, "read_source", args));
    }

    @Test public void searchAndOutputStayBounded() {
        var snapshot = snapshot("needle ".repeat(6000));
        String out = tool(snapshot, "search_sources", Map.of("query", "needle"));
        assertEquals(12, out.chars().filter(c -> c == '@').count()); assertTrue(out.length() <= EvidenceAgentTools.MAX_OUTPUT);
        assertThrows(IllegalArgumentException.class, () -> tool(snapshot, "search_sources", Map.of("query", "x".repeat(129))));
    }
}
