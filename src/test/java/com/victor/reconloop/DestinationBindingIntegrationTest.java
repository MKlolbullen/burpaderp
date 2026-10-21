package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class DestinationBindingIntegrationTest {
    private static final String URL = "https://api.example.test:8443/search?q=secret";
    private static ScanRun run(int cap) { return ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), cap); }
    private static ActiveRequestGateway gateway(FakeMontoya fake) {
        return new ActiveRequestGateway(RequestPolicy.safeDefault(fake.inScope), fake.transport());
    }
    private static ActiveRequestGateway.Result send(FakeMontoya fake, ScanRun run, String url) {
        HttpRequest request = fake.request(url).withHeader("Host", "api.example.test:8443").withHeader("Authorization", "captured");
        return gateway(fake).send(run, RequestPlan.safe(request, "test"), request);
    }

    @Test public void actualMontoyaDispatchUsesValidatedIpWithOriginalBytesAndSni() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            AtomicInteger lookups = new AtomicInteger();
            fake.resolver = host -> { assertEquals("api.example.test", host); return List.of(lookups.getAndIncrement() == 0 ? "93.184.216.34" : "127.0.0.1"); };
            ScanRun run = run(3);
            HttpRequest original = fake.request(URL).withHeader("Host", "api.example.test:8443").withHeader("Authorization", "captured");
            var result = gateway(fake).send(run, RequestPlan.safe(original, "test"), original);
            assertTrue(result.dispatched()); assertNull(result.error());
            HttpRequest sent = fake.sent.getFirst();
            assertEquals("93.184.216.34", sent.httpService().host());
            assertEquals(8443, sent.httpService().port()); assertTrue(sent.httpService().secure());
            assertArrayEquals(original.toByteArray().getBytes(), sent.toByteArray().getBytes());
            assertEquals(List.of("api.example.test"), fake.serverNames);
            assertEquals("api.example.test", result.response().request().httpService().host());
            assertArrayEquals(sent.toByteArray().getBytes(), result.response().request().toByteArray().getBytes());
            assertEquals(1, lookups.get()); // No second name lookup between check and send.
            var rebound = send(fake, run, URL);
            assertEquals(RequestPolicy.DecisionCode.PROTECTED_DESTINATION, rebound.decision().code());
            assertEquals(1, fake.sent.size()); assertEquals(1, run.requestBudget().used());
        }
    }

    @Test public void mixedProtectedEmptyInvalidAndFailedAnswersSpendNoTokensOrDispatches() {
        try (FakeMontoya fake = new FakeMontoya()) {
            for (List<String> answers : List.of(List.of("93.184.216.34", "::1"), List.of("127.0.0.1", "93.184.216.34"),
                    List.of("93.184.216.34", "fd00:ec2::254"), List.of("another.name.test"), List.of("127.1"), List.<String>of())) {
                fake.resolver = host -> answers;
                ScanRun run = run(3);
                assertFalse(send(fake, run, URL).dispatched());
                assertEquals(0, run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
            }
            fake.resolver = host -> { throw new java.net.UnknownHostException("sensitive resolver diagnostic"); };
            var denied = send(fake, run(3), URL);
            assertEquals(RequestPolicy.DecisionCode.DESTINATION_UNAVAILABLE, denied.decision().code());
            assertFalse(denied.decision().reason().contains("sensitive"));
        }
    }

    @Test public void literalAddressesNeverUseDnsAndMappedAliasesCannotEscape() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.resolver = host -> { throw new AssertionError("Literal resolution is forbidden"); };
            assertTrue(send(fake, run(2), "http://8.8.8.8/").dispatched());
            assertTrue(send(fake, run(2), "https://[2606:4700:4700::1111]/").dispatched());
            assertFalse(send(fake, run(2), "http://[::ffff:127.0.0.1]/").dispatched());
            assertEquals(2, fake.sent.size()); assertTrue(fake.dnsLookups.isEmpty());
        }
    }

    @Test public void cancellationAndScopeChangeDuringDnsAreRecheckedBeforeReservation() {
        try (FakeMontoya fake = new FakeMontoya()) {
            ScanRun cancelled = run(3);
            fake.resolver = host -> { cancelled.cancel(); return List.of("93.184.216.34"); };
            assertEquals(RequestPolicy.DecisionCode.CANCELLED, send(fake, cancelled, URL).decision().code());
            assertEquals(0, cancelled.requestBudget().used());
            ScanRun changedScope = run(3);
            java.util.concurrent.atomic.AtomicBoolean scope = new java.util.concurrent.atomic.AtomicBoolean(true);
            fake.inScope = url -> scope.get();
            fake.resolver = host -> { scope.set(false); return List.of("93.184.216.34"); };
            assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE, send(fake, changedScope, URL).decision().code());
            assertEquals(0, changedScope.requestBudget().used()); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void resolverTimeoutCapacityFailureAndInterruptionFailClosed() throws Exception {
        ExecutorService worker = Executors.newSingleThreadExecutor();
        CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
        try {
            DestinationGuard guard = new DestinationGuard(DestinationGuard.bounded(host -> {
                entered.countDown(); release.await(); return List.of("93.184.216.34");
            }, worker, Duration.ofMillis(50)));
            var error = assertThrows(DestinationGuard.Rejected.class, () -> guard.resolve("api.example.test"));
            assertEquals(RequestPolicy.DecisionCode.DESTINATION_UNAVAILABLE, error.code);
            assertTrue(entered.await(1, TimeUnit.SECONDS));
            worker.shutdownNow();
            assertThrows(DestinationGuard.Rejected.class, () -> guard.resolve("api.example.test"));
            DestinationGuard interrupted = new DestinationGuard(host -> { throw new InterruptedException(); });
            assertThrows(DestinationGuard.Rejected.class, () -> interrupted.resolve("api.example.test"));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted(); release.countDown(); worker.shutdownNow(); }
    }

    @Test public void changedBytesOrIgnoredNumericServiceFailBeforeQuota() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            HttpRequest original = fake.request(URL);
            for (boolean ignore : List.of(true, false)) {
                HttpRequest broken = FakeMontoya.proxy(HttpRequest.class, (self, method, args) -> {
                    if (method.getName().equals("withService")) return ignore ? original : original.withService((burp.api.montoya.http.HttpService) args[0]).withHeader("X-Changed", "value");
                    try { return method.invoke(original, args); }
                    catch (java.lang.reflect.InvocationTargetException e) { throw e.getCause(); }
                });
                ScanRun run = run(2);
                var denied = gateway(fake).send(run, RequestPlan.safe(broken, "test"), broken);
                assertEquals(RequestPolicy.DecisionCode.DESTINATION_BINDING_FAILED, denied.decision().code());
                assertFalse(denied.dispatched()); assertEquals(0, run.requestBudget().used());
            }
            assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void everyRedirectHopIsResolvedAndProtectedNameIsNeverDispatched() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.resolver = host -> List.of(host.equals("private.example.test") ? "169.254.169.254" : "93.184.216.34");
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake, new ManualExecutor());
            try {
                fake.responder = request -> FakeMontoya.response(302, "", Map.of("Location", "https://private.example.test/metadata"));
                controller.crawlOne(ReconControllerRunLifecycleTest.item("/start"));
                assertEquals(List.of("api.example.test", "private.example.test"), fake.dnsLookups);
                assertEquals(1, fake.sent.size()); assertEquals(1, controller.currentCrawlRun().requestBudget().used());
            } finally { controller.shutdown(); }
        }
    }

    @Test public void deniedRunsScopePermissionsAndEmptyGlobalBudgetDoNotResolve() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.resolver = host -> { throw new AssertionError("Denied requests must not resolve"); };
            ScanRun cancelled = run(3); cancelled.cancel();
            assertFalse(send(fake, cancelled, URL).dispatched());
            assertFalse(send(fake, run(0), URL).dispatched());
            fake.inScope = url -> false;
            assertFalse(send(fake, run(3), URL).dispatched());
            fake.inScope = url -> true;
            HttpRequest post = fake.request(URL).withMethod("POST");
            assertFalse(gateway(fake).send(run(3), RequestPlan.safe(post, "test"), post).dispatched());
            assertTrue(fake.dnsLookups.isEmpty()); assertTrue(fake.sent.isEmpty());
        }
    }

    @Test public void logicalAssociationPreservesReturnedBytesTimingAnnotationsAndMarkerUpdates() {
        try (FakeMontoya fake = new FakeMontoya()) {
            var returned = fake.request(URL).withHeader("X-Burp-Session", "actual returned bytes");
            var marker = FakeMontoya.proxy(burp.api.montoya.core.Marker.class, (self, method, args) -> 0);
            var timing = FakeMontoya.proxy(burp.api.montoya.http.handler.TimingData.class, (self, method, args) -> null);
            var annotations = FakeMontoya.proxy(burp.api.montoya.core.Annotations.class, (self, method, args) -> null);
            var wire = FakeMontoya.proxy(burp.api.montoya.http.message.HttpRequestResponse.class, (self, method, args) -> switch (method.getName()) {
                case "request" -> returned;
                case "response" -> FakeMontoya.response(200, "body", Map.of());
                case "timingData" -> java.util.Optional.of(timing);
                case "annotations" -> annotations;
                case "requestMarkers", "responseMarkers" -> List.of(marker);
                case "withAnnotations", "withRequestMarkers", "withResponseMarkers", "copyToTempFile" -> self;
                default -> throw new AssertionError(method.getName());
            });
            var associated = new LogicalRequestResponse(wire, fake.request("https://logical.example.test:8443/").httpService());
            assertEquals("logical.example.test", associated.httpService().host());
            assertArrayEquals(returned.toByteArray().getBytes(), associated.request().toByteArray().getBytes());
            assertSame(timing, associated.timingData().orElseThrow()); assertSame(annotations, associated.annotations());
            assertEquals(List.of(marker), associated.withRequestMarkers(marker).requestMarkers());
            assertEquals(List.of(marker), associated.withResponseMarkers(marker).responseMarkers());
            assertEquals("logical.example.test", associated.copyToTempFile().request().httpService().host());
        }
    }

    @Test public void previewNeverResolvesDnsAndDoesNotPretendToApproveDestinations() {
        try (FakeMontoya fake = new FakeMontoya()) {
            fake.resolver = host -> { throw new AssertionError("Preview must stay offline"); };
            var request = fake.request(URL);
            var step = new NativeRequestStep(request, RequestPlan.safe(request, "test"), NativeRequestStep.Mutation.JWT_BASELINE, List.of(), false);
            String report = RequestPreview.inspect(run(3), RequestPolicy.safeDefault(url -> true), List.of(step)).render();
            assertTrue(report.contains("DNS")); assertTrue(fake.dnsLookups.isEmpty());
        }
    }
}
