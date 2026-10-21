package com.victor.reconloop;

import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import java.nio.file.Files;
import java.util.concurrent.TimeUnit;
import java.util.*;
import static org.junit.Assert.*;

public class RuntimeVerificationCasesTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    private static String config() { return "{\"host\":\"fixture.example.test\",\"address\":\"93.184.216.34\",\"httpPort\":18080,\"httpsPort\":18443,\"directResolver\":\"controlled\",\"profile\":\"direct-test\"}"; }
    @Test public void productionGatewayCasesMeterSixDispatchesAndKeepApiEvidenceWithoutReleaseAttestation() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.responder = request -> FakeMontoya.response(request.url().endsWith("/redirect") ? 302 : 200, "fixture",
                    request.url().endsWith("/redirect") ? Map.of("Location", "http://127.0.0.1/denied") : Map.of());
            var runner = new RuntimeVerificationCases(fake.api); List<String> checkpoints = new ArrayList<>();
            var report = runner.run(RuntimeVerificationCases.Config.parse(config()), r -> checkpoints.add(Json.write(r)));
            var cases = Json.asArray(report.get("cases")); assertEquals(8, cases.size()); assertEquals(6, fake.sent.size());
            assertEquals("COMPLETED", report.get("state")); assertEquals("NOT_EVALUATED", report.get("releaseDecision"));
            assertEquals("NOT_RUN", report.get("physicalPeerVerification")); assertEquals(10, checkpoints.size());
            for (Object item : cases) {
                var row = Json.asObject(item); assertEquals(row.toString(), "MATCH", row.get("apiAdmission"));
                assertEquals("MATCH", row.get("responseObservation")); assertEquals("NOT_EVALUATED", row.get("wireStatus"));
                assertEquals("SIGNAL", Json.asObject(row.get("evidence")).get("verificationState"));
                var exchanges = Json.asArray(Json.asObject(row.get("evidence")).get("exchanges"));
                assertEquals(Json.asArray(row.get("markers")).size(), exchanges.size());
            }
            assertTrue(fake.sent.stream().allMatch(r -> r.httpService().host().equals("93.184.216.34")));
            assertEquals(1, fake.serverNames.stream().filter("fixture.example.test"::equals).count());
            assertTrue(fake.scopeChanges.isEmpty()); assertFalse(fake.apiAccesses.contains("collaborator"));
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }
    @Test public void scopeAndCancellationPreventTrafficAndCheckpointPartialState() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.inScope = u -> false;
            var report = new RuntimeVerificationCases(fake.api).run(RuntimeVerificationCases.Config.parse(config()), r -> {});
            assertEquals("NOT_RUN", report.get("state")); assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty());
            fake.inScope = u -> true; var runner = new RuntimeVerificationCases(fake.api);
            fake.onSend = request -> runner.cancel(); List<String> snapshots = new ArrayList<>();
            report = runner.run(RuntimeVerificationCases.Config.parse(config()), r -> snapshots.add(Json.write(r)));
            assertEquals("CANCELLED", report.get("state")); assertEquals(1, fake.sent.size());
            assertEquals(1, Json.asArray(report.get("cases")).size());
            assertEquals("RUNNING", Json.asObject(Json.parseStrict(snapshots.getFirst())).get("state"));
            assertEquals("CANCELLED", Json.asObject(Json.parseStrict(snapshots.getLast())).get("state"));
        }
    }
    @Test public void invalidUnboundedOrProtectedConfigurationCannotReachExecution() {
        for (String json : List.of(config().replace("93.184.216.34", "127.0.0.1"), config().replace("93.184.216.34", "192.0.2.1"),
                config().replace("18080", "0"), config().replace("18443", "65536"), config().replace("18080", "18080.5"),
                config().replace("fixture.example.test", "user:password@target.test"), config().replace("controlled", "ignore-policy"),
                config().replace("\"host\":", "\"extra\":true,\"host\":"), config().replace("direct-test", "x".repeat(300)))) {
            assertThrows(json, IllegalArgumentException.class, () -> RuntimeVerificationCases.Config.parse(json));
        }
    }
    @Test public void checkpointFailureStopsTheExperimentBeforeAnyDispatch() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var runner = new RuntimeVerificationCases(fake.api);
            assertThrows(IllegalStateException.class, () -> runner.run(RuntimeVerificationCases.Config.parse(config()), r -> { throw new IllegalStateException("disk full"); }));
            assertTrue(fake.sent.isEmpty());
        }
    }
    @Test public void loadingTheSeparateExtensionDoesNotStartRequestsOrChangeScope() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            new RuntimeVerificationExtension().initialize(fake.api);
            javax.swing.SwingUtilities.invokeAndWait(() -> {});
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.scopeChanges.isEmpty());
            assertFalse(fake.apiAccesses.contains("http")); assertFalse(fake.apiAccesses.contains("collaborator"));
        }
    }
    @Test public void realJavaReportAndObservedFakeApiBytesRoundTripThroughPythonProtocol() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            String session = UUID.randomUUID().toString(); List<Map<String, Object>> events = new ArrayList<>();
            events.add(RuntimeVerificationCases.obj("fixtureVersion", 1, "sessionId", session, "event", "listen"));
            fake.responder = request -> {
                String id = UUID.randomUUID().toString(), marker = request.headerValue("X-Recon-Hound-Verification");
                boolean tls = request.httpService().secure();
                var response = FakeMontoya.response(request.url().endsWith("/redirect") ? 302 : 200, "synthetic fixture", Map.of());
                events.add(RuntimeVerificationCases.obj("fixtureVersion", 1, "sessionId", session, "event", "tcp_accept", "connectionId", id,
                        "localAddress", request.httpService().host(), "localPort", request.httpService().port()));
                if (tls) events.add(RuntimeVerificationCases.obj("fixtureVersion", 1, "sessionId", session, "event", "tls", "connectionId", id,
                        "serverName", fake.serverNames.getLast(), "protocol", "TLSv1.3"));
                var received = RuntimeVerificationCases.obj("fixtureVersion", 1, "sessionId", session, "event", "http_request", "connectionId", id,
                        "localAddress", request.httpService().host(), "localPort", request.httpService().port(), "host", request.headerValue("Host"),
                        "tls", tls, "serverName", tls ? fake.serverNames.getLast() : "", "tlsProtocol", tls ? "TLSv1.3" : "", "marker", marker);
                addEventBytes(received, "request", request.toByteArray().getBytes()); events.add(received);
                var sent = RuntimeVerificationCases.obj("fixtureVersion", 1, "sessionId", session, "event", "http_response", "connectionId", id, "marker", marker);
                addEventBytes(sent, "response", response.toByteArray().getBytes()); events.add(sent);
                return response;
            };
            var report = new RuntimeVerificationCases(fake.api).run(RuntimeVerificationCases.Config.parse(config()), r -> {});
            events.add(RuntimeVerificationCases.obj("fixtureVersion", 1, "sessionId", session, "event", "fixture_stop"));
            var api = folder.newFile("api.json").toPath(); var log = folder.newFile("fixture.jsonl").toPath();
            var output = folder.getRoot().toPath().resolve("comparison.json");
            Files.writeString(api, Json.write(report)); Files.writeString(log, events.stream().map(Json::write).reduce("", (a,b) -> a + b + "\n"));
            Process process = new ProcessBuilder("python3", "tools/runtime-verification/reconcile.py", "--api-report", api.toString(),
                    "--fixture-log", log.toString(), "--output", output.toString()).redirectErrorStream(true).start();
            try {
                assertTrue(process.waitFor(10, TimeUnit.SECONDS));
                assertEquals(new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8), 0, process.exitValue());
                var result = Json.asObject(Json.parseStrict(Files.readString(output)));
                assertEquals(Boolean.TRUE, result.get("consistentObservations")); assertEquals("NOT_RUN", result.get("physicalPeerVerification"));
            } finally { process.destroyForcibly(); }
        }
    }
    private static void addEventBytes(Map<String, Object> target, String prefix, byte[] bytes) {
        target.put(prefix + "Length", bytes.length); target.put(prefix + "Base64", Base64.getEncoder().encodeToString(bytes));
        target.put(prefix + "Sha256", FindingEvidence.digest(bytes));
    }
}
