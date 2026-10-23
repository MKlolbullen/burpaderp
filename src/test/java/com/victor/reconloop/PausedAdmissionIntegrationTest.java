package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class PausedAdmissionIntegrationTest {
    private static final String URL = "https://api.example.test/search?q=a";

    @Test public void resumedRequestRechecksScopeAfterItsQuotaWasReserved() throws Exception {
        try (var fake = new FakeMontoya()) {
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 1);
            CountDownLatch paused = new CountDownLatch(1);
            var request = pauseOnBindingAfterAdmission(fake.request(URL), run, paused);
            var plan = RequestPlan.safe(request, "probe");
            var gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(fake.api.scope()::isInScope), fake.transport());
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                Future<ActiveRequestGateway.Result> pending = worker.submit(() -> gateway.send(run, plan, request));
                assertTrue(paused.await(3, TimeUnit.SECONDS)); assertEquals(1, run.requestBudget().used());
                assertTrue(fake.sent.isEmpty()); fake.inScope = ignored -> false; assertTrue(run.resume());
                var result = pending.get(3, TimeUnit.SECONDS);
                assertFalse("A saved admission cannot authorize a URL removed from scope while paused", result.dispatched());
                assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE, result.decision().code());
                assertEquals(1, run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
                assertEquals(0, run.snapshot().metrics().dispatched()); assertEquals(1, run.snapshot().metrics().denied());
            } finally { run.cancel(); worker.shutdownNow(); }
        }
    }

    @Test public void resumedAllowedRequestKeepsItsSingleReservation() throws Exception {
        try (var fake = new FakeMontoya()) {
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 1);
            CountDownLatch paused = new CountDownLatch(1);
            var request = pauseOnBindingAfterAdmission(fake.request(URL), run, paused);
            var plan = RequestPlan.safe(request, "probe");
            var gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(fake.api.scope()::isInScope), fake.transport());
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                var pending = worker.submit(() -> gateway.send(run, plan, request));
                assertTrue(paused.await(3, TimeUnit.SECONDS)); assertTrue(run.resume());
                assertTrue(pending.get(3, TimeUnit.SECONDS).dispatched());
                assertEquals(1, run.requestBudget().used()); assertEquals(1, fake.sent.size());
                assertFalse(gateway.send(run, plan, request).dispatched()); assertEquals(1, fake.sent.size());
            } finally { run.cancel(); worker.shutdownNow(); }
        }
    }

    @Test public void cancellationFromTheFinalScopeCheckPreventsTheDispatchCommit() {
        try (var fake = new FakeMontoya()) {
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 1);
            fake.inScope = ignored -> { if (run.requestBudget().used() > 0) run.cancel(); return true; };
            var request = fake.request(URL);
            var result = new ActiveRequestGateway(RequestPolicy.safeDefault(fake.api.scope()::isInScope), fake.transport())
                    .send(run, RequestPlan.safe(request, "probe"), request);
            assertFalse(result.dispatched()); assertEquals(RequestPolicy.DecisionCode.CANCELLED, result.decision().code());
            assertEquals(1, run.requestBudget().used()); assertTrue(fake.sent.isEmpty());
            assertEquals(0, run.snapshot().metrics().dispatched());
        }
    }

    @Test public void pauseDuringAdmissionWaitsInsteadOfDroppingTheProbe() throws Exception {
        try (var fake = new FakeMontoya()) {
            var run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 1);
            CountDownLatch paused = new CountDownLatch(1); var checks = new AtomicInteger();
            // The second scope check is quota admission, after numeric destination preparation.
            var policy = RequestPolicy.safeDefault(ignored -> {
                if (checks.incrementAndGet() == 2) { run.pause(); paused.countDown(); }
                return true;
            });
            var gateway = new ActiveRequestGateway(policy, fake.transport());
            var request = fake.request(URL); var plan = RequestPlan.safe(request, "probe");
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                var pending = worker.submit(() -> gateway.send(run, plan, request));
                assertTrue(paused.await(3, TimeUnit.SECONDS));
                try { pending.get(100, TimeUnit.MILLISECONDS); fail("Paused work must not be returned as a completed denial"); }
                catch (TimeoutException expected) { }
                assertEquals(0, run.requestBudget().used()); assertTrue(run.resume());
                assertTrue(pending.get(3, TimeUnit.SECONDS).dispatched()); assertEquals(1, run.requestBudget().used());
            } finally { run.cancel(); worker.shutdownNow(); }
        }
    }

    private static HttpRequest pauseOnBindingAfterAdmission(HttpRequest base, ScanRun run, CountDownLatch paused) {
        var once = new AtomicBoolean();
        return FakeMontoya.proxy(HttpRequest.class, (self, method, args) -> {
            if (method.getName().equals("toByteArray") && run.requestBudget().used() > 0 && once.compareAndSet(false, true)) {
                run.pause(); paused.countDown();
            }
            return method.invoke(base, args);
        });
    }
}
