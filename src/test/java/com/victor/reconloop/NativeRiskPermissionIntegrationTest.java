package com.victor.reconloop;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;

import java.util.EnumSet;
import java.util.Set;
import static org.junit.Assert.*;

public class NativeRiskPermissionIntegrationTest {
    private ScanRun exercise(FakeMontoya fake, HttpRequest request, Set<RequestPolicy.Permission> grants) {
        ActiveTestEngine engine = new ActiveTestEngine(fake.api, 0);
        engine.setCollaborator(FakeMontoya.proxy(CollaboratorClient.class, (self, method, args) ->
                method.getName().equals("generatePayload")
                        ? FakeMontoya.proxy(CollaboratorPayload.class, (p, call, values) ->
                                call.getName().equals("toString") ? "callback.example.test" : null) : null));
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 4096);
        engine.test(request, run, new ActiveRequestGateway(new RequestPolicy(url -> true, grants),
                fake.transport()));
        assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        return run;
    }

    @Test public void getProbesRequireIndependentOastDelayAndAuthGrants() {
        for (RequestPolicy.Permission grant : Set.of(RequestPolicy.Permission.OAST,
                RequestPolicy.Permission.TIME_DELAY, RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT)) {
            try (FakeMontoya fake = new FakeMontoya()) {
                HttpRequest request = fake.request("https://api.example.test/login?q=a");
                ScanRun denied = exercise(fake, request, Set.of());
                assertEquals(0, denied.probeRequests("ssrf"));
                assertEquals(0, denied.probeRequests("rate-limit"));
                assertFalse(hasDelay(fake)); fake.sent.clear();
                ScanRun allowed = exercise(fake, request, Set.of(grant));
                assertEquals(grant == RequestPolicy.Permission.OAST, allowed.probeRequests("ssrf") > 0);
                assertEquals(grant == RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT, allowed.probeRequests("rate-limit") > 0);
                assertEquals(grant == RequestPolicy.Permission.TIME_DELAY, hasDelay(fake));
                assertEquals("Blind XSS also needs the separate persistent grant", 0, allowed.probeRequests("blind-xss"));
            }
        }
    }

    @Test public void methodGrantDoesNotAuthorizeUploadMutation() {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest upload = fake.request("https://api.example.test/upload").withMethod("POST")
                    .withUpdatedHeader("Content-Type", "multipart/form-data; boundary=boundary")
                    .withBody("--boundary\r\nContent-Disposition: form-data; name=\"avatar\"; filename=\"photo.jpg\"\r\n"
                            + "Content-Type: image/jpeg\r\n\r\nfile\r\n--boundary--\r\n");
            EnumSet<RequestPolicy.Permission> grants = EnumSet.of(RequestPolicy.Permission.UNSAFE_HTTP_METHOD,
                    RequestPolicy.Permission.STATE_CHANGING);
            ScanRun denied = exercise(fake, upload, grants);
            assertEquals(0, denied.probeRequests("file-upload"));
            assertTrue("No other probe may replay the captured multipart file without UPLOAD", fake.sent.isEmpty());
            assertEquals(0, denied.requestBudget().used());
            grants.add(RequestPolicy.Permission.UPLOAD);
            ScanRun allowed = exercise(fake, upload, grants);
            assertTrue(allowed.probeRequests("file-upload") > 0);
            assertEquals(0, allowed.probeRequests("ssrf"));
            assertEquals(0, allowed.probeRequests("rate-limit"));
        }
    }

    @Test public void blindXssNeedsBothIndependentGrantsAndOnlyProducesPendingSignalEvidence() {
        var oast = RequestPolicy.Permission.OAST;
        var persistent = RequestPolicy.Permission.PERSISTENT_PAYLOAD;
        for (Set<RequestPolicy.Permission> grants : java.util.List.of(Set.<RequestPolicy.Permission>of(),
                Set.of(oast), Set.of(persistent), Set.of(oast, persistent))) {
            try (var fake = new FakeMontoya()) {
                var engine = new ActiveTestEngine(fake.api, 0);
                engine.setCollaborator(NativeEvidenceIntegrationTest.collaborator(new java.util.ArrayList<>()));
                var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 4096);
                var findings = engine.test(fake.request("https://api.example.test/search?q=a"), run,
                        new ActiveRequestGateway(new RequestPolicy(url -> true, grants), fake.transport()));
                boolean both = grants.containsAll(Set.of(oast, persistent));
                assertEquals(grants.toString(), both, run.probeRequests("blind-xss") > 0);
                var beacons = findings.stream().filter(f -> f.testClass().equals("XSS-blind")).toList();
                assertEquals(both, !beacons.isEmpty());
                assertTrue(beacons.stream().allMatch(f -> f.verificationState() == VerificationState.SIGNAL));
                assertEquals(grants.contains(oast), run.probeRequests("ssrf") > 0);
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            }
        }
    }

    @Test public void grantingBothBrowserRisksDoesNotAuthorizeNonSafeMethods() {
        try (var fake = new FakeMontoya()) {
            var engine = new ActiveTestEngine(fake.api, 0);
            engine.setCollaborator(NativeEvidenceIntegrationTest.collaborator(new java.util.ArrayList<>()));
            var request = fake.request("https://api.example.test/search?q=a").withMethod("POST");
            var grants = EnumSet.of(RequestPolicy.Permission.OAST, RequestPolicy.Permission.PERSISTENT_PAYLOAD);
            var denied = ScanRun.begin(ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.empty(), 4096);
            engine.test(request, denied, new ActiveRequestGateway(new RequestPolicy(url -> true, grants), fake.transport()));
            assertTrue(fake.sent.isEmpty()); assertEquals(0, denied.requestBudget().used());
            grants.add(RequestPolicy.Permission.UNSAFE_HTTP_METHOD); grants.add(RequestPolicy.Permission.STATE_CHANGING);
            var allowed = ScanRun.begin(ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.empty(), 4096);
            engine.test(request, allowed, new ActiveRequestGateway(new RequestPolicy(url -> true, grants), fake.transport()));
            assertTrue(allowed.probeRequests("blind-xss") > 0);
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }

    private static boolean hasDelay(FakeMontoya fake) {
        return fake.sent.stream().anyMatch(r -> r.parameters().stream().anyMatch(p ->
                p.value().contains("SLEEP") || p.value().contains("WAITFOR")));
    }
}
