package com.victor.reconloop;

import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.*;

public class RequestPolicyTest {

    @Test
    public void permitsInScopeSafeHttpRequest() {
        ScanRun run = run();
        RequestPolicy policy = RequestPolicy.safeDefault(url -> url.contains("example.test"));

        RequestPolicy.Decision decision = policy.evaluate(run,
                RequestPolicy.PlannedRequest.safe("GET", "https://api.example.test/search", "parameter-discovery"));

        assertTrue(decision.allowed());
        assertEquals(RequestPolicy.DecisionCode.ALLOW, decision.code());
    }

    @Test
    public void requiresExplicitPermissionForUnsafeMethodAndDeclaredRisk() {
        ScanRun run = run();
        RequestPolicy policy = RequestPolicy.safeDefault(url -> true);
        RequestPolicy.PlannedRequest planned = new RequestPolicy.PlannedRequest("POST", "https://api.example.test/login",
                "login-check", Set.of(RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT));

        RequestPolicy.Decision denied = policy.evaluate(run, planned);
        assertFalse(denied.allowed());
        assertEquals(RequestPolicy.DecisionCode.MISSING_PERMISSION, denied.code());
        assertTrue(denied.missingPermissions().contains(RequestPolicy.Permission.UNSAFE_HTTP_METHOD));
        assertTrue(denied.missingPermissions().contains(RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT));

        RequestPolicy permitted = new RequestPolicy(url -> true, Set.of(
                RequestPolicy.Permission.UNSAFE_HTTP_METHOD,
                RequestPolicy.Permission.AUTHENTICATION_OR_LOCKOUT));
        assertTrue(permitted.evaluate(run, planned).allowed());
    }

    @Test
    public void blocksOutOfScopeAndProtectedDestinationsBeforeDispatch() {
        ScanRun run = run();
        RequestPolicy policy = RequestPolicy.safeDefault(url -> true);

        assertEquals(RequestPolicy.DecisionCode.PROTECTED_DESTINATION,
                policy.evaluate(run, RequestPolicy.PlannedRequest.safe("GET", "http://169.254.169.254/latest/meta-data", "test")).code());
        assertEquals(RequestPolicy.DecisionCode.PROTECTED_DESTINATION,
                policy.evaluate(run, RequestPolicy.PlannedRequest.safe("GET", "http://[::1]/", "test")).code());
        assertEquals(RequestPolicy.DecisionCode.PROTECTED_DESTINATION,
                policy.evaluate(run, RequestPolicy.PlannedRequest.safe("GET", "http://metadata.google.internal/", "test")).code());

        RequestPolicy scoped = RequestPolicy.safeDefault(url -> false);
        assertEquals(RequestPolicy.DecisionCode.OUT_OF_SCOPE,
                scoped.evaluate(run, RequestPolicy.PlannedRequest.safe("GET", "https://api.example.test/", "test")).code());
    }

    @Test
    public void doesNotTreatOrdinaryHostnameBeginningWithFdAsIpv6() {
        ScanRun run = run();
        RequestPolicy policy = RequestPolicy.safeDefault(url -> true);

        assertTrue(policy.evaluate(run,
                RequestPolicy.PlannedRequest.safe("GET", "https://fd.example.test/", "test")).allowed());
    }

    @Test
    public void rejectsCancelledOrNonHttpRunRequests() {
        ScanRun cancelled = run();
        assertTrue(cancelled.cancel());
        RequestPolicy policy = RequestPolicy.safeDefault(url -> true);
        assertEquals(RequestPolicy.DecisionCode.CANCELLED,
                policy.evaluate(cancelled, RequestPolicy.PlannedRequest.safe("GET", "https://api.example.test/", "test")).code());
        assertEquals(RequestPolicy.DecisionCode.INVALID_REQUEST,
                policy.evaluate(run(), RequestPolicy.PlannedRequest.safe("FILE", "file:///tmp/x", "test")).code());
    }

    private static ScanRun run() {
        return ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 5);
    }
}
