package com.victor.reconloop;

import org.junit.Test;
import javax.swing.SwingUtilities;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import static org.junit.Assert.*;

public class EvidenceAgentIntegrationTest {
    static ReconController controller(FakeMontoya fake, LlmClient client) {
        return new ReconController(fake.api, new ReconModel.FindingTableModel(), new ReconModel.DiscoveryTableModel(),
                new ReconModel.ParameterTableModel(), new ReconModel.ReflectionTableModel(), new ReconModel.ActiveTableModel(),
                new ReconModel.AssetTableModel(), Executors.newSingleThreadExecutor(), false, fake.destinations(), client);
    }
    static String envelope(LlmProvider provider, String text) {
        return switch (provider) {
            case ANTHROPIC -> Json.write(Map.of("stop_reason", "end_turn", "content", List.of(Map.of("type", "text", "text", text))));
            case GEMINI -> Json.write(Map.of("candidates", List.of(Map.of("finishReason", "STOP", "content", Map.of("parts", List.of(Map.of("text", text)))))));
            default -> Json.write(Map.of("choices", List.of(Map.of("finish_reason", "stop", "message", Map.of("content", text)))));
        };
    }

    @Test public void fiveProviderJobsUseRealAdaptersAndNeverSendToATargetOrPersistTheAnalysis() throws Exception {
        try (var fake = new FakeMontoya()) {
            AtomicInteger calls = new AtomicInteger(); AtomicReference<EvidenceAgentRunner.Outcome> result = new AtomicReference<>();
            var client = new LlmClient(request -> {
                var job = EvidenceAgentJobs.JOBS.get(calls.getAndIncrement());
                List<String> ids = EvidenceAgentJobs.reviewer(job) ? List.of("poc:1") : List.of();
                return new LlmClient.Reply(200, envelope(job.role().defaultProvider(), EvidenceAgentRunnerTest.result(job.id(), ids)));
            });
            var controller = controller(fake, client); CountDownLatch done = new CountDownLatch(1);
            try {
                controller.runEvidenceAgentJobs(EvidenceAgentJobsTest.plan(0), event -> {}, outcome -> { result.set(outcome); done.countDown(); });
                assertTrue(done.await(5, TimeUnit.SECONDS)); assertEquals(EvidenceAgentRunner.State.COMPLETED, result.get().state());
                assertEquals(5, calls.get()); assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.issues.isEmpty());
                SwingUtilities.invokeAndWait(() -> {
                    var feed = controller.aiFeedSnapshot(); assertEquals(5, feed.stream().filter(e -> e.kind() == AiFeed.Kind.AGENT_JOB).count());
                    assertFalse(feed.toString().contains("innerHTML")); assertFalse(feed.toString().contains("FAKE-PRIVATE-KEY"));
                });
            } finally { controller.shutdown(); }
            assertFalse(fake.persisted.values().toString().contains("innerHTML")); assertFalse(fake.persisted.values().toString().contains("FAKE-PRIVATE-KEY"));
        }
    }

    @Test public void cancellingTheActualClientStopsLaterJobs() throws Exception {
        try (var fake = new FakeMontoya()) {
            AtomicInteger calls = new AtomicInteger(); CountDownLatch started = new CountDownLatch(1), done = new CountDownLatch(1);
            AtomicReference<EvidenceAgentRunner.Outcome> result = new AtomicReference<>();
            var controller = controller(fake, new LlmClient(request -> {
                calls.incrementAndGet(); started.countDown(); new CountDownLatch(1).await(); throw new AssertionError();
            }));
            try {
                var future = controller.runEvidenceAgentJobs(EvidenceAgentJobsTest.plan(1), event -> {}, outcome -> { result.set(outcome); done.countDown(); });
                assertTrue(started.await(5, TimeUnit.SECONDS)); future.cancel(true); assertTrue(done.await(5, TimeUnit.SECONDS));
                assertEquals(1, calls.get()); assertEquals(EvidenceAgentRunner.State.CANCELLED, result.get().state());
                assertTrue(result.get().tools().isEmpty()); assertTrue(fake.sent.isEmpty()); assertTrue(fake.issues.isEmpty());
            } finally { controller.shutdown(); }
        }
    }
}
