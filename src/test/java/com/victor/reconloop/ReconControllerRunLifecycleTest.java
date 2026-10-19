package com.victor.reconloop;

import org.junit.Test;
import java.net.URI;
import java.util.Map;
import java.util.concurrent.*;
import static org.junit.Assert.*;

public class ReconControllerRunLifecycleTest {
    private static final String ROOT = "https://api.example.test";

    static ReconController controller(FakeMontoya fake, ManualExecutor executor) {
        return new ReconController(fake.api, new ReconModel.FindingTableModel(),
                new ReconModel.DiscoveryTableModel(), new ReconModel.ParameterTableModel(),
                new ReconModel.ReflectionTableModel(), new ReconModel.ActiveTableModel(),
                new ReconModel.AssetTableModel(), executor, false, fake.destinations());
    }

    @Test public void disablingDuringEngineLoopStopsTheNextSend() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor);
            try {
                fake.siteMap.add(FakeMontoya.pair(fake.request(ROOT + "/search?q=a"), FakeMontoya.response(200, "", Map.of())));
                controller.setActiveTestsEnabled(true);
                fake.onSend = request -> controller.setActiveTestsEnabled(false);
                controller.runActiveTests(); executor.runAll();
                assertEquals(1, fake.sent.size());
                assertTrue(fake.errors.toString(), fake.errors.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void queuedJobsCannotSurviveDisableAndReenableOrReset() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor);
            try {
                controller.setActiveTestsEnabled(true);
                controller.discoverParameters(ROOT + "/search");
                controller.setActiveTestsEnabled(false); controller.setActiveTestsEnabled(true);
                executor.runAll(); assertTrue(fake.sent.isEmpty());
                controller.discoverParameters(ROOT + "/search"); controller.reset();
                executor.runAll(); assertTrue(fake.sent.isEmpty());
                controller.discoverParameters(ROOT + "/search"); executor.runAll();
                assertFalse("Freshly requested work must still run", fake.sent.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void revokingMethodPermissionInvalidatesQueuedGraphql() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor);
            try {
                controller.setActiveTestsEnabled(true); controller.setMutatingActiveRequests(true);
                controller.fuzzGraphql(ROOT + "/graphql");
                controller.setMutatingActiveRequests(false);
                executor.runAll(); assertTrue(fake.sent.isEmpty());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void shutdownDuringEngineLoopCancelsBeforeExecutorShutdown() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor);
            fake.siteMap.add(FakeMontoya.pair(fake.request(ROOT + "/search?q=a"), FakeMontoya.response(200, "", Map.of())));
            controller.setActiveTestsEnabled(true);
            fake.onSend = request -> controller.shutdown();
            controller.runActiveTests(); executor.runAll();
            assertEquals(1, fake.sent.size()); assertTrue(executor.isShutdown());
        }
    }

    @Test public void crawlUsesOneRunAcrossUrlsAndPauseDoesNotRefillItsCap() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = controller(fake, new ManualExecutor());
            try {
                controller.setMaxRequests(3);
                controller.crawlOne(item("/a"));
                ScanRun run = controller.currentCrawlRun();
                controller.crawlOne(item("/b"));
                assertSame(run, controller.currentCrawlRun());
                assertEquals(2, run.requestBudget().used());
                controller.pause(); assertTrue(run.isCancelled());
                controller.resume(); controller.crawlOne(item("/c")); controller.crawlOne(item("/d"));
                assertEquals(3, fake.sent.size());
                assertEquals(1, controller.currentCrawlRun().requestBudget().limit());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void crawlPauseDuringResponseStopsTheNextRedirect() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ReconController controller = controller(fake, new ManualExecutor());
            try {
                fake.responder = request -> FakeMontoya.response(302, "", Map.of("Location", "/next"));
                fake.onSend = request -> controller.pause();
                controller.crawlOne(item("/start")); assertEquals(1, fake.sent.size());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void cancellationDoesNotWaitForAnInFlightHttpResponse() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor);
            CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                fake.siteMap.add(FakeMontoya.pair(fake.request(ROOT + "/search?q=a"), FakeMontoya.response(200, "", Map.of())));
                fake.onSend = request -> {
                    entered.countDown();
                    try { assertTrue(release.await(5, TimeUnit.SECONDS)); }
                    catch (InterruptedException e) { throw new AssertionError(e); }
                };
                controller.setActiveTestsEnabled(true); controller.runActiveTests();
                Future<?> job = worker.submit(() -> { executor.runAll(); return null; });
                assertTrue(entered.await(5, TimeUnit.SECONDS));
                controller.setActiveTestsEnabled(false);
                release.countDown(); job.get(5, TimeUnit.SECONDS);
                assertEquals(1, fake.sent.size());
            } finally { release.countDown(); worker.shutdownNow(); controller.shutdown(); }
        }
    }

    @Test public void disableDuringPreparationCannotOpenAFreshRunAfterReenable() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = controller(fake, executor);
            CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                fake.inScope = url -> {
                    entered.countDown();
                    try { assertTrue(release.await(5, TimeUnit.SECONDS)); }
                    catch (InterruptedException e) { throw new AssertionError(e); }
                    return true;
                };
                controller.setActiveTestsEnabled(true); controller.discoverParameters(ROOT + "/search");
                Future<?> job = worker.submit(() -> { executor.runAll(); return null; });
                assertTrue(entered.await(5, TimeUnit.SECONDS));
                controller.setActiveTestsEnabled(false); controller.setActiveTestsEnabled(true);
                release.countDown(); job.get(5, TimeUnit.SECONDS);
                assertTrue(fake.sent.isEmpty());
            } finally { release.countDown(); worker.shutdownNow(); controller.shutdown(); }
        }
    }

    static ReconController.QueueItem item(String path) {
        URI uri = URI.create(ROOT + path); return new ReconController.QueueItem(uri, URI.create(ROOT), "test");
    }
}
