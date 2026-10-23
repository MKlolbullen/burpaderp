package com.victor.reconloop;

import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Set;
import static org.junit.Assert.*;

public class CorpusRiskPermissionIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();

    @Test public void encodedCorpusCallbackAndTimingRequireBothGrantsAndChargeTheBaseline() throws Exception {
        Files.writeString(folder.newFile("sqli.txt").toPath(), "curl https://original.example.test/ ; SLEEP(5)\n");
        try (FakeMontoya fake = new FakeMontoya()) {
            CorpusFuzzEngine engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            engine.setCollaborator(FakeMontoya.proxy(CollaboratorClient.class, (self, method, args) ->
                    FakeMontoya.proxy(CollaboratorPayload.class, (p, call, values) -> "callback.example.test")));
            var request = fake.request("https://api.example.test/search?q=a");
            Set<RequestPolicy.Permission> both = Set.of(RequestPolicy.Permission.TIME_DELAY, RequestPolicy.Permission.OAST);
            for (Set<RequestPolicy.Permission> grants : java.util.List.of(Set.<RequestPolicy.Permission>of(),
                    Set.of(RequestPolicy.Permission.TIME_DELAY), Set.of(RequestPolicy.Permission.OAST), both)) {
                fake.sent.clear();
                ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2);
                engine.fuzz(request, request.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.BASE64), 2,
                        run, new ActiveRequestGateway(new RequestPolicy(url -> true, grants), fake.transport()));
                int expected = grants.equals(both) ? 2 : 0;
                assertEquals(expected, fake.sent.size()); assertEquals(expected, run.requestBudget().used());
                if (expected > 0) {
                    String payload = new String(Base64.getDecoder().decode(fake.sent.getLast().parameters().getFirst().value()), StandardCharsets.UTF_8);
                    assertTrue(payload.contains("callback.example.test")); assertFalse(payload.contains("original.example.test"));
                }
            }
            fake.sent.clear();
            ScanRun one = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 1);
            engine.fuzz(request, request.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.BASE64), 2,
                    one, new ActiveRequestGateway(new RequestPolicy(url -> true, both), fake.transport()));
            assertTrue("A timing pair cannot spend the last single token", fake.sent.isEmpty());
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }
    @Test public void persistentBrowserGrantDoesNotUnblockDestructiveCorpusEntries() throws Exception {
        Files.writeString(folder.newFile("rce.txt").toPath(), "?cmd={payload}\n");
        Files.writeString(folder.newFile("rce_payloads.txt").toPath(),
                "net user fixture /add\necho fixture > fixture.php\necho recon-test\n");
        try (var fake = new FakeMontoya()) {
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            var request = fake.request("https://api.example.test/search?cmd=x");
            var parameter = request.parameters().getFirst();
            var encodings = Set.of(PayloadEncoder.Encoding.RAW);
            var planned = NativeProbePreviewIntegrationTest.materialize(engine.plan(request, parameter, encodings, 10));
            assertEquals(1, planned.size());
            var run = ScanRun.begin(ScanProfile.ACTIVE_MUTATION, ScopeSnapshot.empty(), 100);
            var grants = java.util.EnumSet.allOf(RequestPolicy.Permission.class);
            engine.fuzz(request, parameter, encodings, 10, run,
                    new ActiveRequestGateway(new RequestPolicy(url -> true, grants), fake.transport()));
            assertEquals(1, fake.sent.size());
            assertEquals("echo recon-test", fake.sent.getFirst().parameters().getFirst().value());
            assertTrue(planned.getFirst().plan().matches(fake.sent.getFirst().withService(request.httpService())));
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }
}
