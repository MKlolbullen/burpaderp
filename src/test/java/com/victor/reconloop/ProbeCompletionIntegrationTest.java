package com.victor.reconloop;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.nio.file.Files;
import java.util.*;
import static org.junit.Assert.*;

public class ProbeCompletionIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();
    private static final String URL = "https://api.example.test/search?q=control";
    private static final Set<RequestPolicy.Permission> DELAY = Set.of(RequestPolicy.Permission.TIME_DELAY);

    @Test public void shortCorpusTimingSamplesStayRetryableEvenWhenNoDelayWasObserved() throws Exception {
        try (var fake = new FakeMontoya()) {
            Files.writeString(folder.getRoot().toPath().resolve("sqli.txt"), "SLEEP(5)\n");
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            var request = fake.request(URL);
            for (int cap : List.of(1, 2, 4, 5, 6)) {
                var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), cap);
                var history = new RunHistory(); history.register(run);
                var findings = engine.fuzz(request, request.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.RAW), cap, run,
                        new ActiveRequestGateway(new RequestPolicy(ignored -> true, DELAY), fake.transport(), () -> 0));
                assertTrue(findings.isEmpty()); run.complete();
                var status = run.snapshot().probes().getFirst().status();
                assertEquals("cap=" + cap, cap < 6 ? RunRecord.ProbeStatus.INCONCLUSIVE : RunRecord.ProbeStatus.CHECKED, status);
                assertEquals(cap < 6 ? 1 : 0, history.retries(run.id().toString()).size());
                var restored = new RunHistory(); restored.restore(RunHistoryCodec.decode(RunHistoryCodec.encode(history.snapshot())).runs());
                assertEquals(history.retries(run.id().toString()), restored.retries(run.id().toString()));
            }
        }
    }

    @Test public void rateLimitedTimingResponseIsInconclusiveRatherThanChecked() throws Exception {
        try (var fake = new FakeMontoya()) {
            Files.writeString(folder.getRoot().toPath().resolve("sqli.txt"), "SLEEP(5)\n");
            var engine = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            var request = fake.request(URL); fake.responder = ignored -> FakeMontoya.response(429, "slow down", Map.of());
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 6);
            engine.fuzz(request, request.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.RAW), 6, run,
                    new ActiveRequestGateway(new RequestPolicy(ignored -> true, DELAY), fake.transport(), () -> 0));
            assertEquals(1, fake.sent.size()); assertEquals(RunRecord.ProbeStatus.INCONCLUSIVE, run.snapshot().probes().getFirst().status());
        }
    }

    @Test public void quotaTruncatedNativeProbeIsNotACompletedNegative() {
        try (var fake = new FakeMontoya()) {
            var request = fake.request(URL); var point = InsertionPoint.enumerate(request).getFirst();
            String key = RunRecord.probeKey("NATIVE_ACTIVE", "sqli", RunRecord.target(request.method(), request.url()), RunRecord.pointIdentity(point), "");
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 1);
            var findings = new ActiveTestEngine(fake.api, 0).test(request, run,
                    new ActiveRequestGateway(new RequestPolicy(ignored -> true, DELAY), fake.transport()), Set.of(key));
            assertTrue(findings.isEmpty()); assertEquals(1, fake.sent.size());
            assertEquals(RunRecord.ProbeStatus.INCONCLUSIVE, run.snapshot().probes().getFirst().status());
        }
    }
    @Test public void mutationConstructionFailureRemainsFailedAndRetryableWithoutSending() {
        try (var fake = new FakeMontoya()) {
            var original = fake.request(URL);
            var request = FakeMontoya.proxy(burp.api.montoya.http.message.requests.HttpRequest.class, (self, method, args) -> {
                if (method.getName().equals("withUpdatedParameters")) throw new IllegalStateException("mutation fixture failure");
                return method.invoke(original, args);
            });
            var point = InsertionPoint.enumerate(request).getFirst();
            String key = RunRecord.probeKey("NATIVE_ACTIVE", "reflected-xss", RunRecord.target(request.method(), request.url()), RunRecord.pointIdentity(point), "");
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 2);
            var history = new RunHistory(); history.register(run);
            new ActiveTestEngine(fake.api, 0).test(request, run,
                    new ActiveRequestGateway(RequestPolicy.safeDefault(ignored -> true), fake.transport()), Set.of(key));
            run.complete(); assertTrue(fake.sent.isEmpty()); assertEquals(0, run.requestBudget().used());
            assertEquals(RunRecord.ProbeStatus.FAILED, history.retries(run.id().toString()).getFirst().status());
        }
    }

}
