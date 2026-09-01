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
