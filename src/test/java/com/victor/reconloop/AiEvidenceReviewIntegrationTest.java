package com.victor.reconloop;

import org.junit.Test;
import javax.swing.SwingUtilities;
import java.util.List;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class AiEvidenceReviewIntegrationTest {
    private static final List<LlmClient.LlmCredential> CREDS = List.of(
            new LlmClient.LlmCredential(LlmProvider.OPENAI, "m1", "fake-key"),
            new LlmClient.LlmCredential(LlmProvider.VENICE, "m2", "fake-key-2"));

    private static ReconController controller(FakeMontoya fake, LlmClient client) {
        return new ReconController(fake.api, new ReconModel.FindingTableModel(), new ReconModel.DiscoveryTableModel(),
                new ReconModel.ParameterTableModel(), new ReconModel.ReflectionTableModel(), new ReconModel.ActiveTableModel(),
                new ReconModel.AssetTableModel(), Executors.newSingleThreadExecutor(), false, fake.destinations(), client);
    }
    private static String envelope(String text) {
        return Json.write(Map.of("choices", List.of(Map.of("finish_reason", "stop", "message", Map.of("content", text)))));
    }

    @Test public void oneCallPerProviderAndNoTargetTrafficIssuesOrPromptPersistence() throws Exception {
        try (var fake = new FakeMontoya()) {
            AtomicInteger calls = new AtomicInteger();
            LlmClient client = new LlmClient(request -> {
                calls.incrementAndGet();
                return new LlmClient.Reply(200, envelope(AiAnalysisTest.response(AiAnalysisTest.finding("s1", "innerHTML"))));
            });
            ReconController controller = controller(fake, client);
            List<AiAnalysis.ProviderReport> reports = new CopyOnWriteArrayList<>(); CountDownLatch done = new CountDownLatch(1);
            try {
                controller.reviewEvidence(CREDS, AiAnalysisTest.snapshot(), reports::add, done::countDown).get(5, TimeUnit.SECONDS);
                assertTrue(done.await(5, TimeUnit.SECONDS)); SwingUtilities.invokeAndWait(() -> {});
                assertEquals(2, calls.get()); assertEquals(2, reports.size());
                assertEquals(1, reports.getFirst().report().findings().size());
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.issues.isEmpty());
            } finally { controller.shutdown(); }
            assertFalse(fake.persisted.values().toString().contains("innerHTML"));
            assertFalse(fake.persisted.values().toString().contains("fake-key"));
        }
    }

    @Test public void providerErrorDoesNotBecomeAFindingOrPreventIndependentSecondReview() throws Exception {
        try (var fake = new FakeMontoya()) {
            AtomicInteger calls = new AtomicInteger();
            var controller = controller(fake, new LlmClient(request -> calls.incrementAndGet() == 1
                    ? new LlmClient.Reply(429, "sensitive provider body") : new LlmClient.Reply(200, envelope("{\"findings\":[]}"))));
            List<AiAnalysis.ProviderReport> reports = new CopyOnWriteArrayList<>(); CountDownLatch done = new CountDownLatch(1);
            try {
                controller.reviewEvidence(CREDS, AiAnalysisTest.snapshot(), reports::add, done::countDown);
                assertTrue(done.await(5, TimeUnit.SECONDS)); assertEquals(2, reports.size());
                assertNotNull(reports.getFirst().report().error()); assertFalse(reports.getFirst().report().error().contains("sensitive"));
                assertNull(reports.getLast().report().error()); assertTrue(reports.getLast().report().findings().isEmpty());
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.issues.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void cancellingAnInflightCallPreventsSendingToTheNextProvider() throws Exception {
        try (var fake = new FakeMontoya()) {
            AtomicInteger calls = new AtomicInteger(); CountDownLatch started = new CountDownLatch(1), interrupted = new CountDownLatch(1);
            var controller = controller(fake, new LlmClient(request -> {
                calls.incrementAndGet(); started.countDown();
                try { new CountDownLatch(1).await(); throw new AssertionError(); }
                catch (InterruptedException e) { interrupted.countDown(); throw e; }
            }));
            CountDownLatch done = new CountDownLatch(1);
            try {
                var future = controller.reviewEvidence(CREDS, AiAnalysisTest.snapshot(), report -> fail("Cancelled result must not publish"), done::countDown);
                assertTrue(started.await(5, TimeUnit.SECONDS)); future.cancel(true);
                assertTrue(interrupted.await(5, TimeUnit.SECONDS)); assertTrue(done.await(5, TimeUnit.SECONDS));
                assertEquals(1, calls.get()); assertTrue(fake.sent.isEmpty()); assertTrue(fake.issues.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void duplicateProvidersAreRejectedBeforeAnyCall() {
        try (var fake = new FakeMontoya()) {
            var controller = controller(fake, new LlmClient(request -> { fail("Invalid selection must not send"); return null; }));
            try {
                assertThrows(IllegalArgumentException.class, () -> controller.reviewEvidence(
                        List.of(CREDS.getFirst(), CREDS.getFirst()), AiAnalysisTest.snapshot(), report -> {}, () -> {}));
            } finally { controller.shutdown(); }
        }
    }
}
