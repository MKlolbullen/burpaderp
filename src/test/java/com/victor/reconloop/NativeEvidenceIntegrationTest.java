package com.victor.reconloop;

import burp.api.montoya.collaborator.*;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import javax.swing.SwingUtilities;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;

public class NativeEvidenceIntegrationTest {
    static final String ROOT = "https://api.example.test";
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    static void flush() throws Exception { SwingUtilities.invokeAndWait(() -> {}); }
    static ReconController controller(FakeMontoya fake, ManualExecutor executor, ReconModel.ActiveTableModel active,
                                      ReconModel.FindingTableModel findings) {
        return new ReconController(fake.api, findings, new ReconModel.DiscoveryTableModel(), new ReconModel.ParameterTableModel(),
                new ReconModel.ReflectionTableModel(), active, new ReconModel.AssetTableModel(), executor, false, fake.destinations());
    }

    static CollaboratorClient collaborator(List<String> customData) {
        return FakeMontoya.proxy(CollaboratorClient.class, (self, method, args) -> {
            if (method.getName().equals("getAllInteractions")) return List.of();
            String id = "token" + customData.size(); customData.add((String) args[0]);
            InteractionId identifier = FakeMontoya.proxy(InteractionId.class, (p, call, values) -> id);
            return FakeMontoya.proxy(CollaboratorPayload.class, (p, call, values) -> switch (call.getName()) {
                case "id" -> identifier; case "toString" -> id + ".oast.test";
                case "customData" -> Optional.of(args[0]); default -> null;
            });
        });
    }

    @Test public void nativeFindingsKeepOnlyTheirProbeAndInsertionPointSequence() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var base = fake.request(ROOT + "/search?foo=one&bar=two");
            fake.responder = request -> FakeMontoya.response(200, request.parameters().stream().anyMatch(p -> p.value().equals("'"))
                    ? "You have an error in your SQL syntax" : request.parameters().stream().map(p -> p.value()).reduce("", (a,b) -> a + " " + b), Map.of("X-Evidence", "retained"));
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 300);
            var findings = new ActiveTestEngine(fake.api, 0).test(base, run,
                    new ActiveRequestGateway(new RequestPolicy(url -> true, Set.of()), fake.transport()));
            var sql = findings.stream().filter(f -> f.testClass().equals("SQLi")).toList();
            assertEquals(2, sql.size());
            assertNotEquals(sql.getFirst().evidenceRecord().captureId(), sql.getLast().evidenceRecord().captureId());
            for (var finding : sql) {
                var evidence = finding.evidenceRecord();
                assertEquals(run.id().toString(), evidence.runId()); assertEquals("sqli", evidence.detectorId());
                assertEquals(2, evidence.exchanges().size()); assertEquals(2, finding.httpEvidence().size());
                assertTrue(evidence.complete()); assertEquals(VerificationState.REPRODUCED, evidence.state());
                assertArrayEquals(base.toByteArray().getBytes(), evidence.originalRequest().decoded());
                assertTrue(evidence.exchanges().stream().allMatch(e -> e.probeId().equals("sqli")));
                for (int i = 0; i < 2; i++) {
                    var rr = finding.httpEvidence().get(i); var exchange = evidence.exchanges().get(i);
                    assertArrayEquals(rr.request().toByteArray().getBytes(), exchange.returnedRequest().decoded());
                    assertArrayEquals(rr.response().toByteArray().getBytes(), exchange.response().decoded());
                }
                assertTrue(new String(evidence.exchanges().getLast().plannedRequest().decoded(), StandardCharsets.UTF_8).contains("%27"));
            }
            assertEquals(2, findings.stream().filter(f -> f.testClass().equals("XSS")).count());
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }

    @Test public void gatewayRecordsDenialAndFailedDispatchWithoutInventingResponseBytes() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var request = fake.request(ROOT + "/search?q=a");
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2);
            var plan = RequestPlan.safe(request, "test");
            var denied = new ActiveRequestGateway(new RequestPolicy(url -> false, Set.of()), fake.transport()).send(run, plan, request);
            assertFalse(denied.exchange().dispatchAttempted()); assertEquals("OUT_OF_SCOPE", denied.exchange().decision());
            assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.sent.isEmpty()); assertEquals(0, run.requestBudget().used());
            var failed = new ActiveRequestGateway(new RequestPolicy(url -> true, Set.of()), r -> { throw new java.io.IOException("must not persist secret error message"); }).send(run, plan, request);
            assertTrue(failed.exchange().dispatchAttempted()); assertEquals("IOException", failed.exchange().errorType());
            assertEquals(FindingEvidence.Capture.UNAVAILABLE, failed.exchange().response().capture());
            assertEquals(1, run.requestBudget().used());
        }
    }

    @Test public void longProbeSequenceKeepsBoundedPacketsAndExplicitOmissionCount() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var request = fake.request(ROOT + "/search?q=a");
            fake.responder = r -> FakeMontoya.response(200, "x".repeat(70_000), Map.of());
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 40);
            var gateway = new ActiveRequestGateway(new RequestPolicy(u -> true, Set.of()), fake.transport());
            var capture = new EvidenceCapture(run, request, "NATIVE_ACTIVE", "long-probe");
            for (int i = 0; i < 40; i++) capture.record(gateway.send(run, RequestPlan.safe(request, "long-probe"), request));
            var evidence = capture.snapshot(VerificationState.CANDIDATE, "bounded sequence");
            assertEquals(40, evidence.attempted()); assertEquals(16, evidence.exchanges().size()); assertEquals(24, evidence.omittedExchanges());
            assertFalse(evidence.complete()); assertTrue(evidence.retainedBytes() <= FindingEvidence.MAX_CASE_BYTES);
            assertEquals(FindingEvidence.Capture.PREFIX, evidence.exchanges().getFirst().response().capture());
            assertTrue(evidence.exchanges().stream().anyMatch(e -> e.response().capture() == FindingEvidence.Capture.OMITTED));
            var row = new ReconModel.ActiveRow("INFO", "test", "q", "observed", "bounded", ROOT, evidence);
            assertEquals(List.of(row), ActiveEvidenceCodec.decode(ActiveEvidenceCodec.encode(List.of(row))).rows());
        }
    }

    @Test public void corpusStoresActualEncodedMutationAndPendingOastEvenWithoutResponse() throws Exception {
        Files.writeString(folder.newFile("sqli.txt").toPath(), "curl https://original.example.test/\n");
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            List<String> correlations = new ArrayList<>(); engine.setCollaborator(collaborator(correlations));
            fake.responder = request -> null;
            var request = fake.request(ROOT + "/search?q=a");
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 5);
            var findings = engine.fuzz(request, request.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.BASE64), 5,
                    run, new ActiveRequestGateway(new RequestPolicy(url -> true, Set.of(RequestPolicy.Permission.OAST)), fake.transport()));
            assertEquals(1, fake.sent.size()); assertEquals(1, findings.size());
            var evidence = findings.getFirst().evidenceRecord();
            assertEquals("CORPUS", evidence.source()); assertEquals("AC2|" + evidence.captureId(), correlations.getFirst());
            assertEquals(VerificationState.SIGNAL, evidence.state()); assertTrue(evidence.issuedTokens().getFirst().dispatchAttempted());
            assertEquals("token0", evidence.issuedTokens().getFirst().payloadId());
            assertArrayEquals(fake.sent.getFirst().toByteArray().getBytes(), evidence.exchanges().getFirst().plannedRequest().decoded());
            assertEquals(FindingEvidence.Capture.UNAVAILABLE, evidence.exchanges().getFirst().response().capture()); assertFalse(evidence.complete());
            String encoded = fake.sent.getFirst().parameters().getFirst().value();
            assertTrue(new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8).contains("token0.oast.test"));
        }
    }

    @Test public void nativeOastIsSeparatedByProbeAndOnlyDispatchedTokensCanCorrelate() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var engine = new ActiveTestEngine(fake.api, 0); List<String> correlations = new ArrayList<>();
            engine.setCollaborator(collaborator(correlations));
            var request = fake.request(ROOT + "/search?q=a");
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 100);
            var findings = engine.test(request, run, new ActiveRequestGateway(new RequestPolicy(url -> true,
                    Set.of(RequestPolicy.Permission.OAST)), fake.transport()));
            var pending = findings.stream().filter(f -> !f.evidenceRecord().issuedTokens().isEmpty()).toList();
            assertTrue(pending.size() >= 2);
            assertEquals(pending.size(), pending.stream().map(f -> f.evidenceRecord().captureId()).distinct().count());
            for (var finding : pending) {
                assertEquals(VerificationState.SIGNAL, finding.verificationState());
                assertTrue(finding.evidenceRecord().issuedTokens().getFirst().dispatchAttempted());
                assertTrue(correlations.contains("AC2|" + finding.evidenceRecord().captureId()));
            }
        }
    }

    @Test public void controllerPersistsRestoresTypedEvidenceAndTriageWithoutAnyTrafficOrIssueRefiling() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var active = new ReconModel.ActiveTableModel(); var findings = new ReconModel.FindingTableModel();
            ManualExecutor executor = new ManualExecutor(); ReconController first = controller(fake, executor, active, findings);
            fake.responder = request -> FakeMontoya.response(200, "{\"data\":{\"__schema\":{\"types\":[{\"name\":\"User\"}]}}}", Map.of());
            first.setActiveTestsEnabled(true); first.setMutatingActiveRequests(true);
            first.introspectGraphql(ROOT + "/graphql"); executor.runAll(); flush();
            var triage = new ReconModel.FindingRow("LOW", "test", "rule", "body", "hint", ROOT, "reviewed");
            SwingUtilities.invokeAndWait(() -> findings.add(triage));
            assertEquals(1, active.getRowCount());
            var rows = active.snapshot(); assertEquals(VerificationState.REPRODUCED, rows.getFirst().verificationState());
            assertFalse(fake.issues.isEmpty());
            AuditIssue issue = (AuditIssue) fake.issues.getFirst();
            assertTrue(issue.detail().contains(rows.getFirst().evidenceRecord().id())); assertEquals(1, issue.requestResponses().size());
            first.shutdown();
            String saved = fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE);
            assertEquals(ActiveEvidenceCodec.Status.CURRENT, ActiveEvidenceCodec.decode(saved).status());
            fake.sent.clear(); fake.dnsLookups.clear(); fake.apiAccesses.clear(); fake.issues.clear();
            var restored = new ReconModel.ActiveTableModel(); var restoredFindings = new ReconModel.FindingTableModel();
            ReconController second = controller(fake, new ManualExecutor(), restored, restoredFindings);
            try {
                flush(); assertEquals(rows, restored.snapshot()); assertEquals(List.of(triage), restoredFindings.snapshot());
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.issues.isEmpty());
                assertFalse(fake.apiAccesses.contains("collaborator"));
            } finally { second.shutdown(); }
            assertEquals(saved, fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE));
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }

    @Test public void controllerMigratesLegacyAndSchemaOneSnapshotsWithoutSideEffects() throws Exception {
        var legacy = List.of(true, false).stream().map(confirmed -> Json.write(Map.of(
                "severity", "HIGH", "testClass", "XSS", "parameter", confirmed.toString(),
                "status", "confirmed exploitable", "evidence", "legacy observation", "url", ROOT,
                "confirmed", confirmed))).toList();
        String schemaZero = "{\"schemaVersion\":0,\"recordCount\":2}\n" + String.join("\n", legacy);
        String schemaOne = Files.readString(java.nio.file.Path.of("src/test/resources/active-evidence-v1.jsonl"));
        for (String snapshot : List.of(schemaZero, schemaOne)) {
            try (var fake = new FakeMontoya()) {
                fake.persisted.put(PersistedState.K_ACTIVE_EVIDENCE, snapshot);
                var active = new ReconModel.ActiveTableModel();
                var first = controller(fake, new ManualExecutor(), active, new ReconModel.FindingTableModel());
                List<ReconModel.ActiveRow> rows;
                try {
                    flush(); rows = active.snapshot();
                    assertEquals(snapshot.equals(schemaZero) ? 2 : 1, rows.size());
                    SwingUtilities.invokeAndWait(() -> {
                        for (int i = 0; i < active.getRowCount(); i++)
                            assertEquals(active.row(i).verificationState().displayLabel(), active.getValueAt(i, 6));
                    });
                    if (snapshot.equals(schemaZero)) {
                        for (var row : rows) {
                            assertEquals(row.parameter().equals("true") ? VerificationState.REPRODUCED : VerificationState.SIGNAL,
                                    row.verificationState());
                            assertEquals("unknown", row.evidenceRecord().detectorVersion());
                            assertEquals("", row.evidenceRecord().runId());
                            assertTrue(row.evidenceRecord().exchanges().isEmpty());
                            assertEquals(FindingEvidence.Capture.UNAVAILABLE, row.evidenceRecord().originalRequest().capture());
                        }
                    } else {
                        assertEquals(ActiveEvidenceCodec.decode(schemaOne).rows(), rows);
                        assertEquals(-1, rows.getFirst().evidenceRecord().exchanges().getFirst().transportElapsedNanos());
                    }
                } finally { first.shutdown(); }
                String migrated = fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE);
                assertEquals(ActiveEvidenceCodec.Status.CURRENT, ActiveEvidenceCodec.decode(migrated).status());
                assertEquals(rows, ActiveEvidenceCodec.decode(migrated).rows());
                var restored = new ReconModel.ActiveTableModel();
                var second = controller(fake, new ManualExecutor(), restored, new ReconModel.FindingTableModel());
                try { flush(); assertEquals(rows, restored.snapshot()); }
                finally { second.shutdown(); }
                assertEquals(migrated, fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE));
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.issues.isEmpty());
                assertFalse(fake.apiAccesses.contains("http")); assertFalse(fake.apiAccesses.contains("collaborator"));
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            }
        }
    }

    @Test public void reflectedXssAndUnthrottledLoginObservationsNeverBecomeReportableIssues() throws Exception {
        try (var fake = new FakeMontoya()) {
            var active = new ReconModel.ActiveTableModel(); var executor = new ManualExecutor();
            var controller = controller(fake, executor, active, new ReconModel.FindingTableModel());
            try {
                var request = fake.request(ROOT + "/login?q=seed");
                fake.siteMap.add(FakeMontoya.pair(request, FakeMontoya.response(200, "captured", Map.of())));
                fake.responder = r -> FakeMontoya.response(200, r.parameterValue("q"), Map.of());
                controller.setActiveTestsEnabled(true); controller.setAuthLockoutActiveRequests(true);
                controller.setActiveRequestBudget(100); controller.setActivePerHostBudget(100);
                controller.setActivePerEndpointBudget(100); controller.setActivePerProbeBudget(1);
                controller.runActiveTests(); executor.runAll(); flush();
                for (String type : List.of("XSS", "RateLimit")) {
                    var observed = active.snapshot().stream().filter(row -> row.testClass().equals(type)).toList();
                    assertFalse(type + " must actually be observed", observed.isEmpty());
                    for (var row : observed) {
                        assertEquals(type.equals("XSS") ? VerificationState.CANDIDATE : VerificationState.SIGNAL,
                                row.verificationState());
                        assertFalse(row.verificationState().isReportable());
                    }
                    assertFalse(fake.issues.stream().map(AuditIssue.class::cast).anyMatch(i -> i.name().contains(type + " (")));
                }
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void unloadPreservesUnreadableSnapshotAndResetExplicitlyRecoversIt() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            for (String old : List.of("{\"schemaVersion\":99}\nfuture", "broken snapshot")) {
                fake.persisted.put(PersistedState.K_ACTIVE_EVIDENCE, old);
                ReconController first = controller(fake, new ManualExecutor(), new ReconModel.ActiveTableModel(), new ReconModel.FindingTableModel());
                flush(); first.shutdown(); assertEquals(old, fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE));
                ReconController second = controller(fake, new ManualExecutor(), new ReconModel.ActiveTableModel(), new ReconModel.FindingTableModel());
                second.reset(); flush(); second.shutdown();
                assertTrue(ActiveEvidenceCodec.decode(fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE)).rows().isEmpty());
                assertTrue(fake.sent.isEmpty());
            }
        }
    }

    @Test public void staleSnapshotsCannotOverwriteNewerSaveOrUndoReset() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var active = new ReconModel.ActiveTableModel();
            var controller = controller(fake, new ManualExecutor(), active, new ReconModel.FindingTableModel());
            var snapshot = ReconController.class.getDeclaredMethod("snapshot", long.class); snapshot.setAccessible(true);
            var write = Arrays.stream(ReconController.class.getDeclaredMethods()).filter(m -> m.getName().equals("writeSnapshot")).findFirst().orElseThrow();
            write.setAccessible(true);
            Object[] saved = new Object[2];
            try {
                SwingUtilities.invokeAndWait(() -> {
                    try {
                        active.add(ActiveEvidenceCodecTest.sample(VerificationState.REPRODUCED)); saved[0] = snapshot.invoke(controller, 0L);
                        active.add(ActiveEvidenceCodecTest.sample(VerificationState.CANDIDATE)); saved[1] = snapshot.invoke(controller, 0L);
                    } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
                });
                write.invoke(controller, saved[1]); String newer = fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE);
                write.invoke(controller, saved[0]); assertEquals(newer, fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE));
                controller.reset(); flush(); write.invoke(controller, saved[1]);
                assertTrue(ActiveEvidenceCodec.decode(fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE)).rows().isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void nativeHelpersCaptureBaselineComparisonsAndConservativeStates() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var active = new ReconModel.ActiveTableModel(); ManualExecutor executor = new ManualExecutor();
            var controller = controller(fake, executor, active, new ReconModel.FindingTableModel());
            try {
                controller.setActiveTestsEnabled(true); controller.setAuthLockoutActiveRequests(true); controller.setActiveRequestBudget(3);
                String token = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"alg\":\"HS256\"}".getBytes(StandardCharsets.UTF_8))
                        + "." + Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"test\"}".getBytes(StandardCharsets.UTF_8)) + ".c2lnbmF0dXJl";
                var request = fake.request(ROOT + "/account").withUpdatedHeader("Authorization", "Bearer " + token);
                fake.siteMap.add(FakeMontoya.pair(request, FakeMontoya.response(200, "private", Map.of())));
                fake.responder = r -> FakeMontoya.response(403, "denied", Map.of());
                controller.runAccessControlTest("", true); executor.runAll(); flush();
                var access = active.row(0).evidenceRecord();
                assertEquals(VerificationState.REJECTED, access.state()); assertEquals("access-control", access.detectorId());
                assertArrayEquals(FakeMontoya.response(200, "private", Map.of()).toByteArray().getBytes(), access.originalResponse().decoded());
                assertEquals(1, access.exchanges().size());
                fake.responder = r -> FakeMontoya.response(200, "same content", Map.of());
                controller.runJwtAttacks(); executor.runAll(); flush();
                var jwt = active.snapshot().stream().filter(r -> r.testClass().equals("JWT-none")).findFirst().orElseThrow().evidenceRecord();
                assertEquals(VerificationState.REPRODUCED, jwt.state()); assertEquals(2, jwt.exchanges().size());
                assertNotEquals(jwt.exchanges().getFirst().plannedRequest().sha256(), jwt.exchanges().getLast().plannedRequest().sha256());
                controller.enqueueSeeds(ROOT + "/");
                fake.responder = r -> FakeMontoya.response(404, "There isn't a GitHub Pages site here", Map.of());
                controller.runSubdomainTakeoverCheck(); executor.runAll(); flush();
                var takeover = active.snapshot().stream().filter(r -> r.testClass().equals("Takeover")).findFirst().orElseThrow().evidenceRecord();
                assertEquals(VerificationState.CANDIDATE, takeover.state()); assertEquals(1, takeover.exchanges().size());
                fake.responder = r -> FakeMontoya.response(200, r.parameters().stream().map(p -> p.value()).reduce("", String::concat), Map.of());
                var discoveries = new ParameterDiscoveryEngine(fake.api, List.of("hidden")).discover(fake.request(ROOT + "/search"),
                        ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 3), new ActiveRequestGateway(new RequestPolicy(u -> true, Set.of()), fake.transport()), 0);
                assertEquals(1, discoveries.size()); assertEquals(VerificationState.REPRODUCED, discoveries.getFirst().evidenceRecord().state());
                assertEquals(2, discoveries.getFirst().evidenceRecord().exchanges().size());
                for (Object issued : fake.issues) assertTrue(((AuditIssue) issued).detail(), ((AuditIssue) issued).detail().contains("Evidence ID:"));
                assertEquals(ActiveEvidenceCodec.Status.CURRENT, ActiveEvidenceCodec.decode(ActiveEvidenceCodec.encode(active.snapshot())).status());
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void resetDuringInFlightNativeResponseCannotRepopulateOrSaveOldEvidence() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            var active = new ReconModel.ActiveTableModel(); ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor, active, new ReconModel.FindingTableModel());
            CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                fake.responder = request -> FakeMontoya.response(200, "{\"data\":{\"__schema\":{\"types\":[]}}}", Map.of());
                fake.onSend = request -> { entered.countDown(); try { assertTrue(release.await(5, TimeUnit.SECONDS)); } catch (InterruptedException e) { throw new AssertionError(e); } };
                controller.setActiveTestsEnabled(true); controller.setMutatingActiveRequests(true);
                controller.introspectGraphql(ROOT + "/graphql"); Future<?> result = worker.submit(() -> { executor.runAll(); return null; });
                assertTrue(entered.await(5, TimeUnit.SECONDS)); controller.reset(); flush(); release.countDown(); result.get(5, TimeUnit.SECONDS); flush();
                assertTrue(active.snapshot().isEmpty()); assertTrue(fake.issues.isEmpty());
            } finally { release.countDown(); worker.shutdownNow(); controller.shutdown(); }
            assertTrue(ActiveEvidenceCodec.decode(fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE)).rows().isEmpty());
        }
    }
}
