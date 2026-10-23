package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import org.junit.Test;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.Assert.*;

public class UploadEvidenceIntegrationTest {
    private static final String ROOT = NativeEvidenceIntegrationTest.ROOT;
    private static final String REPORTED = "{\"url\":\"/uploads/photo.php\"}";
    private static final Set<RequestPolicy.Permission> GRANTS = Set.of(
            RequestPolicy.Permission.UNSAFE_HTTP_METHOD, RequestPolicy.Permission.STATE_CHANGING,
            RequestPolicy.Permission.UPLOAD);

    private static HttpRequest upload(FakeMontoya fake) {
        return fake.request(ROOT + "/upload?q=seed").withMethod("POST")
                .withUpdatedHeader("Content-Type", "multipart/form-data; boundary=boundary")
                .withBody("--boundary\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"photo.jpg\"\r\n"
                        + "Content-Type: image/jpeg\r\n\r\nsynthetic-file-content\r\n--boundary--\r\n");
    }

    @Test public void acceptedUploadAndEchoedDangerousPathRemainSignalsWithoutRetrieval() {
        for (String body : List.of("accepted", REPORTED)) {
            try (var fake = new FakeMontoya()) {
                var base = upload(fake);
                fake.responder = request -> FakeMontoya.response(200, body, Map.of());
                var run = ScanRun.begin(ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.empty(), 4096);
                var findings = new ActiveTestEngine(fake.api, 0).test(base, run,
                        new ActiveRequestGateway(new RequestPolicy(url -> true, GRANTS), fake.transport()))
                        .stream().filter(f -> f.testClass().equals("FileUpload")).toList();
                assertFalse("The upload probe must actually run", findings.isEmpty());
                for (var finding : findings) {
                    assertEquals(VerificationState.SIGNAL, finding.verificationState());
                    var evidence = finding.evidenceRecord();
                    assertEquals(VerificationState.SIGNAL, evidence.state());
                    assertEquals("2", evidence.detectorVersion());
                    assertEquals("file-upload", evidence.detectorId());
                    assertEquals(run.id().toString(), evidence.runId());
                    assertArrayEquals(base.toByteArray().getBytes(), evidence.originalRequest().decoded());
                    assertFalse(evidence.exchanges().isEmpty());
                    for (int i = 0; i < evidence.exchanges().size(); i++) {
                        var exchange = evidence.exchanges().get(i);
                        var live = finding.httpEvidence().get(i);
                        assertEquals("file-upload", exchange.probeId());
                        assertArrayEquals(live.request().toByteArray().getBytes(), exchange.plannedRequest().decoded());
                        assertArrayEquals(live.response().toByteArray().getBytes(), exchange.response().decoded());
                    }
                    if (body.equals(REPORTED)) {
                        assertTrue(finding.evidence().contains("reported path: /uploads/photo.php"));
                        assertTrue(finding.evidence().contains("retrieval not verified"));
                        assertFalse(finding.evidence().contains("stored at"));
                        assertTrue(new String(evidence.exchanges().getFirst().plannedRequest().decoded(),
                                StandardCharsets.UTF_8).contains("filename=\"photo.php\""));
                    }
                }
                assertFalse(fake.sent.stream().anyMatch(r -> URI.create(r.url()).getPath().startsWith("/uploads/")));
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            }
        }
    }

    @Test public void uploadSignalIsNotFiledAndSurvivesControllerReload() throws Exception {
        try (var fake = new FakeMontoya()) {
            var active = new ReconModel.ActiveTableModel();
            var executor = new ManualExecutor();
            var first = NativeEvidenceIntegrationTest.controller(fake, executor, active, new ReconModel.FindingTableModel());
            List<ReconModel.ActiveRow> rows;
            try {
                fake.siteMap.add(FakeMontoya.pair(upload(fake), FakeMontoya.response(200, "captured", Map.of())));
                fake.responder = request -> FakeMontoya.response(200, REPORTED, Map.of());
                first.setActiveTestsEnabled(true); first.setMutatingActiveRequests(true); first.setUploadActiveRequests(true);
                first.setActiveRequestBudget(100); first.setActivePerHostBudget(100);
                first.setActivePerEndpointBudget(100); first.setActivePerProbeBudget(1);
                first.runActiveTests(); executor.runAll(); NativeEvidenceIntegrationTest.flush();
                rows = active.snapshot();
                var uploads = rows.stream().filter(r -> r.testClass().equals("FileUpload")).toList();
                assertEquals(1, uploads.size());
                assertEquals(VerificationState.SIGNAL, uploads.getFirst().verificationState());
                assertEquals("2", uploads.getFirst().evidenceRecord().detectorVersion());
                assertFalse(fake.issues.stream().map(AuditIssue.class::cast).anyMatch(i -> i.name().contains("FileUpload")));
                assertFalse(fake.sent.stream().anyMatch(r -> URI.create(r.url()).getPath().startsWith("/uploads/")));
            } finally { first.shutdown(); }
            assertEquals(rows, ActiveEvidenceCodec.decode(fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE)).rows());
            fake.sent.clear(); fake.dnsLookups.clear(); fake.apiAccesses.clear(); fake.issues.clear();
            var restored = new ReconModel.ActiveTableModel();
            var second = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(), restored, new ReconModel.FindingTableModel());
            try {
                NativeEvidenceIntegrationTest.flush();
                assertEquals(rows, restored.snapshot());
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.issues.isEmpty());
                assertFalse(fake.apiAccesses.contains("http")); assertFalse(fake.apiAccesses.contains("collaborator"));
            } finally { second.shutdown(); }
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }

    @Test public void historicalUploadEvidenceRetainsItsRecordedStateAndDetectorRevision() throws Exception {
        try (var fake = new FakeMontoya()) {
            var sample = ActiveEvidenceCodecTest.sample(VerificationState.REPRODUCED).evidenceRecord();
            var original = upload(fake);
            var mutation = original.withBody(FileUploadEngine.withRenamedFilename(original.bodyToString(), "photo.jpg", "photo.php"));
            var bytes = FindingEvidence.Bytes.capture(mutation.toByteArray().getBytes());
            var exchange = new FindingEvidence.Exchange(sample.exchanges().getFirst().id(), sample.runId(),
                    "file-upload", "POST", original.url(), "ALLOW", true, 1_000, "", bytes, bytes,
                    FindingEvidence.Bytes.capture(FakeMontoya.response(200, REPORTED, Map.of()).toByteArray().getBytes()));
            var historical = new FindingEvidence(sample.id(), sample.captureId(), sample.runId(), sample.source(),
                    "file-upload", "1", sample.state(), sample.observedAt(), "Legacy reported path", sample.reproduction(),
                    FindingEvidence.Bytes.capture(original.toByteArray().getBytes()), List.of(exchange), 1, 0,
                    List.of(), null, List.of());
            var row = new ReconModel.ActiveRow("HIGH", "FileUpload", "avatar", "reproduced", "historical", ROOT, historical);
            fake.persisted.put(PersistedState.K_ACTIVE_EVIDENCE, ActiveEvidenceCodec.encode(List.of(row)));
            var active = new ReconModel.ActiveTableModel();
            var controller = NativeEvidenceIntegrationTest.controller(fake, new ManualExecutor(), active, new ReconModel.FindingTableModel());
            try {
                NativeEvidenceIntegrationTest.flush(); assertEquals(List.of(row), active.snapshot());
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.issues.isEmpty());
                assertFalse(fake.apiAccesses.contains("http")); assertFalse(fake.apiAccesses.contains("collaborator"));
            } finally { controller.shutdown(); }
            assertEquals(List.of(row), ActiveEvidenceCodec.decode(fake.persisted.get(PersistedState.K_ACTIVE_EVIDENCE)).rows());
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }
}
