package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.*;

import static org.junit.Assert.*;

public class OutboundRunIntegrationTest {
    @Rule public TemporaryFolder folder = new TemporaryFolder();

    @Test public void differentEnginesTargetsParametersAndCategoriesShareSevenSends() throws Exception {
        for (String category : List.of("sqli", "xss", "ssti")) {
            Files.writeString(folder.newFile(category + ".txt").toPath(), "one\ntwo\n");
        }
        try (FakeMontoya fake = new FakeMontoya()) {
            ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true),
                    new MontoyaTargetTransport(fake.api));
            ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 7);
            CorpusFuzzEngine corpus = new CorpusFuzzEngine(fake.api, new PayloadLibrary(folder.getRoot().toPath()), 0);
            HttpRequest a = fake.request("https://a.example.test/search?q=a");
            HttpRequest b = fake.request("https://b.example.test/search?r=b");
            corpus.fuzz(a, a.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.RAW), 1, run, gateway);
            assertEquals(3, fake.sent.size());
            corpus.fuzz(b, b.parameters().getFirst(), Set.of(PayloadEncoder.Encoding.RAW), 1, run, gateway);
            assertEquals(6, fake.sent.size());
            new ActiveTestEngine(fake.api, 0).test(fake.request("https://c.example.test/search?s=c"), run, gateway);
            new ParameterDiscoveryEngine(fake.api).discover(fake.request("https://d.example.test/"), run, gateway, 0);
            assertEquals(7, fake.sent.size());
            assertEquals(7, run.requestBudget().used());
            assertEquals(3, fake.sent.stream().map(r -> java.net.URI.create(r.url()).getHost()).distinct().count());
            assertTrue(fake.errors.toString(), fake.errors.isEmpty());
        }
    }

    @Test public void concurrentGatewayDispatchNeverEmitsRequestSeventyFour() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true),
                    new MontoyaTargetTransport(fake.api));
            ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                    new ScanRun.RequestLimits(73, 73, 73, 73));
            HttpRequest request = fake.request("https://api.example.test/search?q=a");
            var planned = RequestPolicy.PlannedRequest.safe("GET", request.url(), "shared");
            ExecutorService workers = Executors.newFixedThreadPool(12);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> futures = new ArrayList<>();
            try {
                for (int i = 0; i < 12; i++) futures.add(workers.submit(() -> {
                    try { start.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); return; }
                    for (int j = 0; j < 100; j++) gateway.send(run, planned, request);
                }));
                start.countDown();
                for (Future<?> future : futures) future.get(5, TimeUnit.SECONDS);
                assertEquals(73, fake.sent.size());
                assertEquals(73, run.requestBudget().used());
                assertEquals(73, run.hostRequests("api.example.test"));
                assertEquals(73, run.endpointRequests("GET", "https://api.example.test:443/search?q=other"));
                assertEquals(73, run.probeRequests("shared"));
            } finally { workers.shutdownNow(); }
        }
    }
    @Test public void concurrentDenialsLeaveEveryQuotaDimensionConsistent() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true),
                    new MontoyaTargetTransport(fake.api));
            ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                    new ScanRun.RequestLimits(100, 7, 3, 4));
            ExecutorService pool = Executors.newFixedThreadPool(8);
            List<Future<?>> futures = new ArrayList<>();
            CountDownLatch start = new CountDownLatch(1);
            try {
                for (int i = 0; i < 8; i++) {
                    String host = "h" + (i % 2) + ".example.test";
                    futures.add(pool.submit(() -> {
                        try { start.await(); } catch (InterruptedException e) { throw new AssertionError(e); }
                        for (int j = 0; j < 90; j++) {
                            HttpRequest request = fake.request("https://" + host + "/p" + (j % 3) + "?q=" + j);
                            gateway.send(run, RequestPolicy.PlannedRequest.safe("GET", request.url(), "p" + (j % 3)), request);
                        }
                    }));
                }
                start.countDown();
                for (Future<?> future : futures) future.get(5, TimeUnit.SECONDS);
                assertEquals(12, fake.sent.size()); assertEquals(12, run.requestBudget().used());
                int hostTotal = 0, endpointTotal = 0, probeTotal = 0;
                for (int h = 0; h < 2; h++) {
                    int used = run.hostRequests("h" + h + ".example.test");
                    assertTrue(used <= 7); hostTotal += used;
                    for (int p = 0; p < 3; p++) {
                        int endpoint = run.endpointRequests("GET", "https://h" + h + ".example.test/p" + p);
                        assertTrue(endpoint <= 3); endpointTotal += endpoint;
                    }
                }
                for (int p = 0; p < 3; p++) { assertEquals(4, run.probeRequests("p" + p)); probeTotal += run.probeRequests("p" + p); }
                assertEquals(12, hostTotal); assertEquals(12, endpointTotal); assertEquals(12, probeTotal);
            } finally { pool.shutdownNow(); }
        }
    }

}
