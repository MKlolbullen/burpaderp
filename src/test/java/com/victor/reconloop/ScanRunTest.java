package com.victor.reconloop;

import org.junit.Test;

import java.util.Set;

import static org.junit.Assert.*;

public class ScanRunTest {

    @Test
    public void beginsRunningWithOneRunScopedBudget() {
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE,
                new ScopeSnapshot(Set.of("api.example.test"), Set.of("203.0.113.0/24")), 2);

        assertNotNull(run.id());
        assertNotNull(run.startedAt());
        assertEquals(RunStatus.RUNNING, run.status());
        assertEquals(2, run.requestBudget().limit());
        assertTrue(run.requestBudget().tryAcquire());
        assertTrue(run.requestBudget().tryAcquire());
        assertFalse(run.requestBudget().tryAcquire());
    }

    @Test
    public void cancellationAndCompletionAreTerminal() {
        ScanRun cancelled = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 1);
        assertTrue(cancelled.cancel());
        assertEquals(RunStatus.CANCELLED, cancelled.status());
        assertNotNull(cancelled.finishedAt());
        assertFalse(cancelled.complete());

        ScanRun completed = ScanRun.begin(ScanProfile.DISCOVERY, ScopeSnapshot.empty(), 1);
        assertTrue(completed.complete());
        assertEquals(RunStatus.COMPLETED, completed.status());
        assertNotNull(completed.finishedAt());
        assertFalse(completed.cancel());
    }

    @Test
    public void failureRecordsReasonAndCannotOverwriteTerminalState() {
        ScanRun run = ScanRun.begin(ScanProfile.EXTERNAL_TOOL, ScopeSnapshot.empty(), 1);
        assertTrue(run.fail("adapter failed"));
        assertEquals(RunStatus.FAILED, run.status());
        assertEquals("adapter failed", run.failureReason());
        assertFalse(run.fail("another failure"));
        assertEquals("adapter failed", run.failureReason());
    }

    @Test
    public void hierarchicalQuotaReservationIsAtomicAndQueryInsensitive() {
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                new ScanRun.RequestLimits(10, 3, 1, 5));

        RequestPolicy.PlannedRequest first = RequestPolicy.PlannedRequest.safe(
                "GET", "https://api.example.test/users?id=1", "idor");
        RequestPolicy.PlannedRequest sameEndpoint = RequestPolicy.PlannedRequest.safe(
                "GET", "https://api.example.test/users?id=2", "idor");

        assertTrue(run.tryAcquire(first).allowed());
        ScanRun.Allocation denied = run.tryAcquire(sameEndpoint);

        assertFalse(denied.allowed());
        assertEquals(ScanRun.Quota.ENDPOINT, denied.exhaustedQuota());
        assertEquals(1, run.requestBudget().used());
        assertEquals(1, run.hostRequests("api.example.test"));
        assertEquals(1, run.endpointRequests("GET", "https://api.example.test/users?anything=else"));
        assertEquals(1, run.probeRequests("idor"));
    }

    @Test
    public void hostAndProbeQuotasPreventOneConsumerFromMonopolisingRun() {
        ScanRun hostLimited = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                new ScanRun.RequestLimits(10, 2, 5, 10));
        assertTrue(hostLimited.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://api.example.test/a", "p1")).allowed());
        assertTrue(hostLimited.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://api.example.test/b", "p2")).allowed());
        ScanRun.Allocation hostDenied = hostLimited.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://api.example.test/c", "p3"));
        assertEquals(ScanRun.Quota.HOST, hostDenied.exhaustedQuota());
        assertEquals(2, hostLimited.requestBudget().used());

        ScanRun probeLimited = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                new ScanRun.RequestLimits(10, 10, 10, 2));
        assertTrue(probeLimited.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://one.example.test/a", "same-probe")).allowed());
        assertTrue(probeLimited.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://two.example.test/b", "same-probe")).allowed());
        ScanRun.Allocation probeDenied = probeLimited.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://three.example.test/c", "same-probe"));
        assertEquals(ScanRun.Quota.PROBE, probeDenied.exhaustedQuota());
        assertEquals(2, probeLimited.requestBudget().used());
    }

    @Test
    public void requestLimitsNeverExceedGlobalLimit() {
        ScanRun.RequestLimits limits = new ScanRun.RequestLimits(7, 99, 50, 8);
        assertEquals(7, limits.global());
        assertEquals(7, limits.perHost());
        assertEquals(7, limits.perEndpoint());
        assertEquals(7, limits.perProbe());
    }
    @Test
    public void explicitDefaultPortsAndQueryMutationsUseSameEndpointQuota() {
        ScanRun run = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(),
                new ScanRun.RequestLimits(10, 10, 1, 10));
        assertTrue(run.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://API.example.test/users?id=1", "test")).allowed());
        ScanRun.Allocation denied = run.tryAcquire(RequestPolicy.PlannedRequest.safe(
                "GET", "https://api.example.test:443/users?id=2", "test"));
        assertEquals(ScanRun.Quota.ENDPOINT, denied.exhaustedQuota());
        assertEquals(1, run.requestBudget().used());
    }

}
