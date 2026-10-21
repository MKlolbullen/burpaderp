package com.victor.reconloop;

import burp.api.montoya.persistence.PersistedObject;
import org.junit.Test;
import java.util.*;
import static org.junit.Assert.*;

public class ActiveEvidenceCodecTest {
    static ReconModel.ActiveRow sample(VerificationState state) {
        var bytes = FindingEvidence.Bytes.capture(new byte[]{0, 1, 13, 10, (byte) 0x80, (byte) 0xff});
        String run = UUID.randomUUID().toString();
        var exchange = new FindingEvidence.Exchange(UUID.randomUUID().toString(), run, "sql-error", "GET",
                "https://api.example.test/?q=%27", "ALLOW", true, Long.MAX_VALUE, "", bytes, bytes, bytes);
        var evidence = new FindingEvidence(UUID.randomUUID().toString(), UUID.randomUUID().toString(), run,
                "NATIVE_ACTIVE", "sql-error", "1", state, "2026-10-21T10:00:00Z", "reason\nwith\ttabs", "fresh authorization required",
                bytes, List.of(exchange), 1, 0, List.of(), null, List.of());
        return new ReconModel.ActiveRow("HIGH", "SQLi", "q", "observation", "text\nwith\ttabs", "https://api.example.test/", evidence);
    }

    static PersistedObject store(Map<String, String> values) {
        return FakeMontoya.proxy(PersistedObject.class, (self, method, args) -> switch (method.getName()) {
            case "getString" -> values.get(args[0]);
            case "setString" -> { values.put((String) args[0], (String) args[1]); yield null; }
            default -> null;
        });
    }

    static String frame(String payload) {
        return Json.write(Map.of("schemaVersion", ActiveEvidenceCodec.VERSION, "recordCount", payload.isEmpty() ? 0 : payload.split("\n", -1).length,
                "payloadSha256", FindingEvidence.digest(payload))) + "\n" + payload;
    }

    @Test public void allStatesRoundTripExactBinaryStableIdsAndLongDuration() {
        var rows = Arrays.stream(VerificationState.values()).map(ActiveEvidenceCodecTest::sample).toList();
        String encoded = ActiveEvidenceCodec.encode(rows);
        var loaded = ActiveEvidenceCodec.decode(encoded);
        assertEquals(ActiveEvidenceCodec.Status.CURRENT, loaded.status());
        assertEquals(rows, loaded.rows()); assertEquals(encoded, ActiveEvidenceCodec.encode(loaded.rows()));
        byte[] decoded = loaded.rows().getFirst().evidenceRecord().originalRequest().decoded();
        assertArrayEquals(new byte[]{0, 1, 13, 10, (byte) 0x80, (byte) 0xff}, decoded);
        decoded[0] = 99;
        assertEquals(0, loaded.rows().getFirst().evidenceRecord().originalRequest().decoded()[0]);
        assertTrue(loaded.rows().getFirst().evidenceRecord().complete());
    }

    @Test public void legacyImportDoesNotInventRawHistoryOrPromoteStatusText() {
        List<String> records = new ArrayList<>();
        for (boolean confirmed : List.of(true, false)) records.add(Json.write(Map.of("severity", "HIGH", "testClass", "XSS",
                "parameter", "q", "status", "confirmed exploitable", "evidence", "legacy", "url", "https://api.example.test/", "confirmed", confirmed)));
        Map<String, String> values = new HashMap<>();
        values.put(PersistedState.K_ACTIVE_EVIDENCE, "{\"schemaVersion\":0,\"recordCount\":2}\n" + String.join("\n", records));
        var loaded = PersistedState.loadActiveEvidence(store(values));
        assertEquals(ActiveEvidenceCodec.Status.MIGRATED, loaded.status());
        assertEquals(VerificationState.REPRODUCED, loaded.rows().getFirst().verificationState());
        assertEquals(VerificationState.SIGNAL, loaded.rows().getLast().verificationState());
        assertEquals("unknown", loaded.rows().getFirst().evidenceRecord().detectorVersion());
        assertFalse(loaded.rows().getFirst().evidenceRecord().complete());
        assertTrue(PersistedState.saveActiveEvidence(store(values), loaded.rows()));
        assertEquals(loaded.rows(), PersistedState.loadActiveEvidence(store(values)).rows());
        assertEquals(ActiveEvidenceCodec.Status.ABSENT, ActiveEvidenceCodec.decode(null).status());
    }

    @Test public void unsupportedCorruptAndTruncatedSnapshotsArePreservedUntilExplicitReset() {
        String good = ActiveEvidenceCodec.encode(List.of(sample(VerificationState.CANDIDATE)));
        for (String old : List.of("{\"schemaVersion\":99,\"recordCount\":1}\nopaque future data", good.substring(0, good.length() - 3),
                good.replace("reason", "tampered"), "broken")) {
            Map<String, String> values = new HashMap<>(Map.of(PersistedState.K_ACTIVE_EVIDENCE, old));
            assertFalse(PersistedState.saveActiveEvidence(store(values), List.of()));
            assertEquals(old, values.get(PersistedState.K_ACTIVE_EVIDENCE));
            PersistedState.resetActiveEvidence(store(values));
            assertEquals(ActiveEvidenceCodec.Status.CURRENT, PersistedState.loadActiveEvidence(store(values)).status());
            assertTrue(PersistedState.loadActiveEvidence(store(values)).rows().isEmpty());
        }
    }

    @Test public void validatesRecordsIndependentlyOfEnvelopeHash() {
        String good = ActiveEvidenceCodec.encode(List.of(sample(VerificationState.REPRODUCED)));
        String payload = good.substring(good.indexOf('\n') + 1);
        for (String bad : List.of(payload.replace("REPRODUCED", "UNRECOGNIZED"), payload.replace("\"severity\":", "\"extra\":1,\"severity\":"),
                payload.replace("AAENC", "AQENC"), payload + "\n" + payload)) {
            assertEquals(bad.substring(0, 40), ActiveEvidenceCodec.Status.CORRUPT, ActiveEvidenceCodec.decode(frame(bad)).status());
        }
    }

    @Test public void truncationIsExplicitAndPreservesFullDigestAndState() {
        byte[] large = new byte[FindingEvidence.MAX_MESSAGE_BYTES + 10]; Arrays.fill(large, (byte) 0xab);
        var captured = FindingEvidence.Bytes.capture(large);
        assertEquals(FindingEvidence.Capture.PREFIX, captured.capture());
        assertEquals(FindingEvidence.digest(large), captured.sha256());
        assertEquals(FindingEvidence.MAX_MESSAGE_BYTES, captured.decoded().length);
        var row = sample(VerificationState.CONFIRMED);
        var evidence = row.evidenceRecord().withOriginalResponse(captured);
        assertFalse(evidence.complete());
        var restored = ActiveEvidenceCodec.decode(ActiveEvidenceCodec.encode(List.of(row.withEvidence(evidence)))).rows().getFirst();
        assertEquals(captured, restored.evidenceRecord().originalResponse());
        assertEquals(VerificationState.CONFIRMED, restored.withEvidence(evidence.withoutBytes()).verificationState());
        assertEquals(captured.sha256(), evidence.withoutBytes().originalResponse().sha256());
    }

    @Test public void tableCapsRowsAndBytesWithoutElevatingUnstructuredStatus() {
        var table = new ReconModel.ActiveTableModel();
        var big = FindingEvidence.Bytes.capture(new byte[FindingEvidence.MAX_MESSAGE_BYTES]);
        for (int i = 0; i < 220; i++) {
            var row = sample(VerificationState.CANDIDATE);
            table.add(row.withEvidence(row.evidenceRecord().withOriginalResponse(big)));
        }
        assertTrue(table.snapshot().stream().mapToInt(r -> r.evidenceRecord().retainedBytes()).sum() <= ReconModel.ActiveTableModel.MAX_RETAINED_BYTES);
        assertTrue(table.snapshot().stream().anyMatch(r -> r.evidenceRecord().originalResponse().capture() == FindingEvidence.Capture.OMITTED));
        for (int i = 0; i < 600; i++) table.add(new ReconModel.ActiveRow("HIGH", "XSS", "q", "confirmed", "legacy", ""));
        assertEquals(500, table.getRowCount());
        assertTrue(table.snapshot().stream().allMatch(r -> r.verificationState() == VerificationState.SIGNAL));
    }

    @Test public void strictJsonRejectsAmbiguousMalformedAndUnboundedInput() {
        for (String malformed : List.of("{\"a\":1,\"a\":2}", "\"bad\\x\"", "\"bad\n\"", "01", "1.", "1e999", "-", "[".repeat(70) + "0" + "]".repeat(70))) {
            try { Json.parseStrict(malformed); fail(malformed); } catch (IllegalArgumentException expected) { }
        }
        assertEquals(1.25, ((Number) Json.parseStrict("1.25")).doubleValue(), 0);
        assertEquals(-125, ((Number) Json.parseStrict("-1.25e2")).doubleValue(), 0);
    }
    @Test public void schemaOneFixtureMigratesWithoutInventingTransportTimeOrChangingEvidence() throws Exception {
        String previous = java.nio.file.Files.readString(java.nio.file.Path.of("src/test/resources/active-evidence-v1.jsonl"));
        var loaded = ActiveEvidenceCodec.decode(previous);
        assertEquals(ActiveEvidenceCodec.Status.MIGRATED, loaded.status());
        var row = loaded.rows().getFirst(); var evidence = row.evidenceRecord();
        assertEquals("cccccccc-cccc-4ccc-8ccc-cccccccccccc", evidence.id()); assertEquals("1", evidence.detectorVersion());
        assertEquals(VerificationState.REPRODUCED,evidence.state()); assertTrue(evidence.complete());
        assertEquals(2_000_000_000L,evidence.exchanges().getFirst().elapsedNanos());
        assertEquals(-1,evidence.exchanges().getFirst().transportElapsedNanos());
        Map<String,String> values = new HashMap<>(Map.of(PersistedState.K_ACTIVE_EVIDENCE,previous));
        assertTrue(PersistedState.saveActiveEvidence(store(values),loaded.rows()));
        var restored = PersistedState.loadActiveEvidence(store(values));
        assertEquals(ActiveEvidenceCodec.Status.CURRENT,restored.status()); assertEquals(loaded.rows(),restored.rows());
        assertEquals(ActiveEvidenceCodec.Status.CORRUPT,ActiveEvidenceCodec.decode(previous+" ").status());
    }
    @Test public void schemaTwoRoundTripsTransportDurationExactlyAndRejectsImpossibleTiming() {
        Map<String,Object> object = ActiveEvidenceCodec.rowMap(sample(VerificationState.REPRODUCED));
        var exchange = Json.asObject(Json.asArray(Json.asObject(object.get("provenance")).get("exchanges")).getFirst());
        exchange.put("transportElapsedNanos",Long.toString(Long.MAX_VALUE));
        var loaded = ActiveEvidenceCodec.decode(frame(Json.write(object)));
        assertEquals(ActiveEvidenceCodec.Status.CURRENT,loaded.status());
        assertEquals(Long.MAX_VALUE,loaded.rows().getFirst().evidenceRecord().exchanges().getFirst().transportElapsedNanos());
        for (String invalid : List.of("-2","01","1.5","9223372036854775808")) {
            exchange.put("transportElapsedNanos",invalid);
            assertEquals(ActiveEvidenceCodec.Status.CORRUPT,ActiveEvidenceCodec.decode(frame(Json.write(object))).status());
        }
        exchange.put("transportElapsedNanos","2"); exchange.put("elapsedNanos","1");
        assertEquals(ActiveEvidenceCodec.Status.CORRUPT,ActiveEvidenceCodec.decode(frame(Json.write(object))).status());
        exchange.put("elapsedNanos","10"); exchange.put("dispatchAttempted",false);
        assertEquals(ActiveEvidenceCodec.Status.CORRUPT,ActiveEvidenceCodec.decode(frame(Json.write(object))).status());
    }
}
