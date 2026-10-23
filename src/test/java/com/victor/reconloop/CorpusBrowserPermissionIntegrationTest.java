package com.victor.reconloop;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;

public class CorpusBrowserPermissionIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    private static final String URL = "https://api.example.test/search?q=a";
    private static final String LOCAL = "<script>alert(1)</script>";
    private static final RequestPolicy.Permission PERSISTENT = RequestPolicy.Permission.PERSISTENT_PAYLOAD;
    private static final RequestPolicy.Permission OAST = RequestPolicy.Permission.OAST;

    @Test public void previewAndRuntimeApplyIndependentGrantsBeforeEveryEncoding() throws Exception {
        Files.writeString(folder.newFile("xss.txt").toPath(), LOCAL + "\n" + CorpusBrowserPolicy.BEACON + "\n<script src=https://foreign.example.test/p.js></script>\n");
        try (var fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            var request = fake.request(URL); var parameter = request.parameters().getFirst();
            for (var encoding : PayloadEncoder.Encoding.values()) {
                var plans = NativeProbePreviewIntegrationTest.materialize(engine.plan(request, parameter, Set.of(encoding), 10));
                assertEquals(2, plans.size());
                assertTrue(plans.stream().allMatch(p -> p.metadata().requiredPermissions().contains(PERSISTENT)));
                assertEquals(Set.of(PERSISTENT, OAST), plans.getLast().metadata().requiredPermissions());
                assertTrue(plans.getLast().template()); assertNull(plans.getLast().plan());
                assertTrue(fake.sent.isEmpty());
                for (Set<RequestPolicy.Permission> grants : List.of(Set.<RequestPolicy.Permission>of(), Set.of(OAST), Set.of(PERSISTENT), Set.of(PERSISTENT, OAST))) {
                    var policy = new RequestPolicy(ignored -> true, grants);
                    var previewRun = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 10);
                    var preview = RequestPreview.inspect(previewRun, policy, plans);
                    assertEquals(grants.contains(PERSISTENT) ? 1 : 0, preview.admitted());
                    assertEquals(grants.containsAll(Set.of(PERSISTENT, OAST)) ? RequestPolicy.DecisionCode.PENDING_BINDING : RequestPolicy.DecisionCode.MISSING_PERMISSION,
                            preview.rows().getLast().decision());
                    assertEquals(0, previewRun.requestBudget().used());
                    engine.setCollaborator(NativeEvidenceIntegrationTest.collaborator(new ArrayList<>()));
                    fake.sent.clear(); fake.dnsLookups.clear();
                    var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 10);
                    engine.fuzz(request, parameter, Set.of(encoding), 10, run, new ActiveRequestGateway(policy, fake.transport()));
                    int expected = grants.contains(PERSISTENT) ? grants.contains(OAST) ? 2 : 1 : 0;
                    assertEquals(grants + " " + encoding, expected, fake.sent.size()); assertEquals(expected, run.requestBudget().used());
                    if (expected == 0) assertTrue(fake.dnsLookups.isEmpty());
                    else assertEquals(PayloadEncoder.encode(LOCAL, encoding), fake.sent.getFirst().parameters().getFirst().value());
                    if (expected == 2) assertEquals(PayloadEncoder.encode(CorpusBrowserPolicy.BEACON.replace(CorpusBrowserPolicy.HOST_MARKER, "token0.oast.test"), encoding),
                            fake.sent.getLast().parameters().getFirst().value());
                    fake.sent.clear();
                }
            }
        }
    }

    @Test public void unknownBrowserEntriesStayQuarantinedWithEveryGrantAndNoCallbackAllocation() throws Exception {
        String unknown = "<script src=https://foreign.example.test/p.js></script>\n"
                + "<script>window.location='https://foreign.example.test'</script>\n"
                + "<img src=x onerror=eval(atob('fixture'))>\n"
                + "%3Cscript%20src=https://foreign.example.test/p.js%3E%3C/script%3E\n";
        Files.writeString(folder.newFile("xss.txt").toPath(), unknown);
        Files.writeString(folder.newFile("ssti.txt").toPath(), "fetch('https://foreign.example.test')\nwindow.location='https://foreign.example.test'\n");
        try (var fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            engine.setCollaborator(FakeMontoya.proxy(burp.api.montoya.collaborator.CollaboratorClient.class,
                    (self, method, args) -> { throw new AssertionError("quarantined browser payload allocated a callback"); }));
            var request = fake.request(URL); var parameter = request.parameters().getFirst(); var encodings = EnumSet.allOf(PayloadEncoder.Encoding.class);
            assertTrue(NativeProbePreviewIntegrationTest.materialize(engine.plan(request, parameter, encodings, 100)).isEmpty());
            var run = ScanRun.begin(ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.forTargetUrl(URL), 100);
            engine.fuzz(request, parameter, encodings, 100, run,
                    new ActiveRequestGateway(new RequestPolicy(ignored -> true, EnumSet.allOf(RequestPolicy.Permission.class)), fake.transport()));
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertEquals(0, run.requestBudget().used());
        }
    }

    @Test public void browserGrantsDoNotAuthorizePostAndPreviewAllocatesNoCallbacks() throws Exception {
        Files.writeString(folder.newFile("xss.txt").toPath(), CorpusBrowserPolicy.BEACON + "\n");
        try (var fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            engine.setCollaborator(FakeMontoya.proxy(burp.api.montoya.collaborator.CollaboratorClient.class,
                    (self, method, args) -> { throw new AssertionError("preview allocated a callback"); }));
            var request = fake.request(URL).withMethod("POST"); var parameter = request.parameters().getFirst();
            var plans = NativeProbePreviewIntegrationTest.materialize(engine.plan(request, parameter, Set.of(PayloadEncoder.Encoding.RAW), 2));
            assertEquals(1, plans.size()); assertTrue(plans.getFirst().metadata().requiredPermissions().contains(RequestPolicy.Permission.UNSAFE_HTTP_METHOD));
            var policy = new RequestPolicy(ignored -> true, Set.of(PERSISTENT, OAST));
            assertEquals(RequestPolicy.DecisionCode.MISSING_PERMISSION, RequestPreview.inspect(
                    ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2), policy, plans).rows().getFirst().decision());
            engine.setCollaborator(NativeEvidenceIntegrationTest.collaborator(new ArrayList<>()));
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2);
            engine.fuzz(request, parameter, Set.of(PayloadEncoder.Encoding.RAW), 2, run, new ActiveRequestGateway(policy, fake.transport()));
            assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertEquals(0, run.requestBudget().used());
        }
    }

    @Test public void typedBrowserCallbackCannotBindAnArbitraryUrlOrMarkup() {
        for (String host : List.of("https://foreign.example.test/", "foreign.example.test/path", "foreign.example.test\"><script>", "127.0.0.1", "")) {
            try { CorpusBrowserPolicy.bind(CorpusBrowserPolicy.BEACON, host); fail("accepted " + host); }
            catch (IllegalArgumentException expected) { }
        }
        assertTrue(CorpusBrowserPolicy.bind(CorpusBrowserPolicy.BEACON, "token.oast.test").contains("//token.oast.test/"));
    }
}
