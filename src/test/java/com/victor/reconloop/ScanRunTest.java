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
}
