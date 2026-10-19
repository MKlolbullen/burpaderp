package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;

import java.lang.reflect.Proxy;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

public class ActiveRequestGatewayTest {

    @Test
    public void dispatchesOnlyApprovedMatchingRequestAndChargesRunBudget() {
        AtomicInteger sent = new AtomicInteger();
        ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true), request -> {
            sent.incrementAndGet();
            return null;
        });
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 1);
        HttpRequest request = fakeRequest("GET", "https://api.example.test/search");
        RequestPolicy.PlannedRequest planned = RequestPolicy.PlannedRequest.safe("GET", request.url(), "parameter-discovery");

        ActiveRequestGateway.Result first = gateway.send(run, planned, request);
        ActiveRequestGateway.Result second = gateway.send(run, planned, request);

        assertTrue(first.dispatched());
        assertNull(first.error());
        assertFalse(second.dispatched());
        assertEquals(RequestPolicy.DecisionCode.BUDGET_EXHAUSTED, second.decision().code());
        assertEquals(1, sent.get());
        assertEquals(1, run.requestBudget().used());
    }

    @Test
    public void refusesMismatchedOrDeniedRequestsWithoutCallingSender() {
        AtomicInteger sent = new AtomicInteger();
        ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> false), request -> {
            sent.incrementAndGet();
            return null;
        });
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 3);
        HttpRequest request = fakeRequest("GET", "https://api.example.test/search");

        ActiveRequestGateway.Result mismatch = gateway.send(run,
                RequestPolicy.PlannedRequest.safe("GET", "https://api.example.test/other", "test"), request);
        ActiveRequestGateway.Result outOfScope = gateway.send(run,
                RequestPolicy.PlannedRequest.safe("GET", request.url(), "test"), request);

        assertEquals(RequestPolicy.DecisionCode.INVALID_REQUEST, mismatch.decision().code());
        assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE, outOfScope.decision().code());
        assertEquals(0, sent.get());
        assertEquals(0, run.requestBudget().used());
    }


    @Test
    public void endpointQuotaDenialDoesNotSpendGlobalBudgetOrDispatch() {
        AtomicInteger sent = new AtomicInteger();
        ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true), request -> {
            sent.incrementAndGet();
            return null;
        });
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                new ScanRun.RequestLimits(5, 5, 1, 5));

        HttpRequest first = fakeRequest("GET", "https://api.example.test/items?id=1");
        HttpRequest second = fakeRequest("GET", "https://api.example.test/items?id=2");

        assertTrue(gateway.send(run,
                RequestPolicy.PlannedRequest.safe("GET", first.url(), "parameter-test"), first).dispatched());

        ActiveRequestGateway.Result denied = gateway.send(run,
                RequestPolicy.PlannedRequest.safe("GET", second.url(), "parameter-test"), second);

        assertFalse(denied.dispatched());
        assertEquals(RequestPolicy.DecisionCode.ENDPOINT_BUDGET_EXHAUSTED, denied.decision().code());
        assertEquals(1, sent.get());
        assertEquals(1, run.requestBudget().used());
    }


    @Test
    public void riskPermissionDenialDoesNotDispatchOrSpendQuota() {
        AtomicInteger sent = new AtomicInteger();
        HttpRequest request = fakeRequest("GET", "https://api.example.test/callback");
        RequestPolicy.PlannedRequest oast = new RequestPolicy.PlannedRequest(
                "GET", request.url(), "ssrf", Set.of(RequestPolicy.Permission.OAST));

        ScanRun deniedRun = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 5);
        ActiveRequestGateway deniedGateway = new ActiveRequestGateway(
                RequestPolicy.safeDefault(url -> true), req -> {
                    sent.incrementAndGet();
                    return null;
                });

        ActiveRequestGateway.Result denied = deniedGateway.send(deniedRun, oast, request);
        assertFalse(denied.dispatched());
        assertEquals(RequestPolicy.DecisionCode.MISSING_PERMISSION, denied.decision().code());
        assertEquals(0, deniedRun.requestBudget().used());
        assertEquals(0, sent.get());

        ScanRun allowedRun = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 5);
        ActiveRequestGateway allowedGateway = new ActiveRequestGateway(
                new RequestPolicy(url -> true, Set.of(RequestPolicy.Permission.OAST)), req -> {
                    sent.incrementAndGet();
                    return null;
                });
        assertTrue(allowedGateway.send(allowedRun, oast, request).dispatched());
        assertEquals(1, allowedRun.requestBudget().used());
        assertEquals(1, sent.get());
    }

    @Test
    public void dispatchExceptionDoesNotRefundQuotaOrPermitRetry() {
        AtomicInteger sent = new AtomicInteger();
        ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> true), request -> {
            sent.incrementAndGet(); throw new java.io.IOException("simulated transport failure");
        });
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 1);
        HttpRequest request = fakeRequest("GET", "https://api.example.test/a");
        var planned = RequestPolicy.PlannedRequest.safe("GET", request.url(), "test");
        var first = gateway.send(run, planned, request);
        assertTrue(first.dispatched()); assertNotNull(first.error());
        assertFalse(gateway.send(run, planned, request).dispatched());
        assertEquals(1, sent.get()); assertEquals(1, run.requestBudget().used());
    }

    @Test
    public void cancellationDuringPolicyEvaluationPreventsDispatch() {
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2);
        AtomicInteger sent = new AtomicInteger();
        ActiveRequestGateway gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(url -> {
            run.cancel(); return true;
        }), request -> { sent.incrementAndGet(); return null; });
        HttpRequest request = fakeRequest("GET", "https://api.example.test/a");
        var result = gateway.send(run, RequestPolicy.PlannedRequest.safe("GET", request.url(), "test"), request);
        assertFalse(result.dispatched());
        assertEquals(RequestPolicy.DecisionCode.CANCELLED, result.decision().code());
        assertEquals(0, sent.get());
        // A cancellation race may conservatively consume a token, but never emits a request.
        assertTrue(run.requestBudget().used() <= 1);
    }

    private static HttpRequest fakeRequest(String methodValue, String urlValue) {
        return (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "method" -> methodValue;
                    case "url" -> urlValue;
                    case "toString" -> methodValue + " " + urlValue;
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> null;
                });
    }
}
