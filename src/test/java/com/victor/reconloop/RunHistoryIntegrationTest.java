package com.victor.reconloop;

import org.junit.Test;
import java.util.*;
import java.util.concurrent.*;
import static org.junit.Assert.*;

public class RunHistoryIntegrationTest {
    private static final String URL = "https://api.example.test/search?q=current-secret";
    private static ScanRun run(int limit) { return ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), limit); }

    @Test public void gatewayAccountsEveryOutcomeAndNeverPersistsCredentialsOrQueryValues() {
        try (var fake = new FakeMontoya()) {
            var history = new RunHistory(); var run = run(2); history.register(run);
            var request = fake.request(URL).withHeader("Authorization", "Bearer private-fixture-value");
            var gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(u -> !u.contains("outside")), fake.transport());
            assertTrue(gateway.send(run, RequestPlan.safe(request, "probe"), request).dispatched());
            fake.onSend = ignored -> { throw new IllegalStateException("credential-private-exception"); };
            assertNotNull(gateway.send(run, RequestPlan.safe(request, "probe"), request).error());
            var outside = fake.request("https://outside.example.test/");
            assertFalse(gateway.send(run, RequestPlan.safe(outside, "probe"), outside).dispatched());
            assertFalse(gateway.send(run, RequestPlan.safe(request, "probe"), request).dispatched());
            var m = run.snapshot().metrics();
            assertEquals(4, m.attempts()); assertEquals(2, m.admitted()); assertEquals(2, m.dispatched());
            assertEquals(1, m.responses()); assertEquals(1, m.errors()); assertEquals(2, m.denied());
            assertEquals(2, fake.sent.size());
            run.complete(); String saved = RunHistoryCodec.encode(history.snapshot());
            assertFalse(saved.contains("current-secret")); assertFalse(saved.contains("private-fixture-value"));
            assertFalse(saved.contains("credential-private-exception")); assertFalse(saved.contains("Authorization"));
            assertEquals(RunHistoryCodec.Status.CURRENT, RunHistoryCodec.decode(saved).status());
            assertEquals(history.snapshot(), RunHistoryCodec.decode(saved).runs());
            assertTrue(run.snapshot().audit().stream().filter(e -> e.kind().equals("REQUEST")).allMatch(e -> e.requestHash().length() == 64));
        }
    }

    @Test public void pauseResumesSameLedgerAndCancelUnblocksOnlyItsOwnRun() throws Exception {
        try (var fake = new FakeMontoya()) {
            var history = new RunHistory(); var first = run(2); var other = run(1); history.register(first); history.register(other);
            var request = fake.request(URL); var gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(u -> true), fake.transport());
            gateway.send(first, RequestPlan.safe(request, "probe"), request);
            assertTrue(history.control(first.id().toString(), "pause"));
            ExecutorService worker = Executors.newSingleThreadExecutor();
            try {
                CountDownLatch entered = new CountDownLatch(1);
                Future<ActiveRequestGateway.Result> waiting = worker.submit(() -> { entered.countDown(); return gateway.send(first, RequestPlan.safe(request, "probe"), request); });
                assertTrue(entered.await(2, TimeUnit.SECONDS));
                try { waiting.get(100, TimeUnit.MILLISECONDS); fail("Paused dispatch must wait"); } catch (TimeoutException expected) { }
                assertEquals(1, first.requestBudget().used()); assertEquals(1, fake.sent.size());
                assertTrue(history.control(first.id().toString(), "resume")); assertTrue(waiting.get(2, TimeUnit.SECONDS).dispatched());
                assertEquals(2, first.requestBudget().used());
                assertFalse(gateway.send(first, RequestPlan.safe(request, "probe"), request).dispatched());
                assertTrue(first.pause());
                Future<ActiveRequestGateway.Result> cancelled = worker.submit(() -> gateway.send(first, RequestPlan.safe(request, "probe"), request));
                assertTrue(history.control(first.id().toString(), "cancel"));
                assertFalse(cancelled.get(2, TimeUnit.SECONDS).dispatched()); assertFalse(first.resume());
                assertTrue(gateway.send(other, RequestPlan.safe(request, "probe"), request).dispatched());
                assertEquals(3, fake.sent.size());
            } finally { worker.shutdownNow(); }
        }
    }

    @Test public void restoringInterruptedHistoryHasNoLiveControlsAndPreservesAccounting() {
        try (var fake = new FakeMontoya()) {
            var first = run(3); var history = new RunHistory(); history.register(first);
            var request = fake.request(URL); new ActiveRequestGateway(RequestPolicy.safeDefault(u -> true), fake.transport()).send(first, RequestPlan.safe(request, "probe"), request);
            first.pause();
            var loaded = RunHistoryCodec.decode(RunHistoryCodec.encode(history.snapshot()));
            var restored = new RunHistory(); restored.restore(loaded.runs());
            var record = restored.get(first.id().toString());
            assertEquals(RunStatus.INTERRUPTED, record.status()); assertEquals(1, record.metrics().admitted());
            assertEquals(first.scope(), record.scope()); assertEquals(first.profile(), record.profile());
            assertFalse(restored.control(record.id(), "resume")); assertFalse(restored.control(record.id(), "cancel"));
            assertEquals(1, fake.sent.size()); assertEquals(RunHistoryCodec.Status.CURRENT, RunHistoryCodec.decode(RunHistoryCodec.encode(restored.snapshot())).status());
        }
    }

    @Test public void boundedAuditKeepsExactTotalsAndExplicitOmissionCount() {
        try (var fake = new FakeMontoya()) {
            var run = run(1); var request = fake.request(URL); var gateway = new ActiveRequestGateway(RequestPolicy.safeDefault(u -> false), fake.transport());
            for (int i = 0; i < 600; i++) gateway.send(run, RequestPlan.safe(request, "probe"), request);
            var record = run.snapshot(); assertEquals(600, record.metrics().denied()); assertEquals(0, record.metrics().admitted());
            assertEquals(RunRecord.MAX_EVENTS, record.audit().size()); assertEquals(89, record.omittedEvents());
            assertTrue(fake.sent.isEmpty()); assertEquals(RunHistoryCodec.Status.CURRENT, RunHistoryCodec.decode(RunHistoryCodec.encode(List.of(record))).status());
        }
    }

    @Test public void futureCorruptOrTamperedHistoryIsPreservedUntilExplicitReset() {
        try (var fake = new FakeMontoya()) {
            var store = fake.api.persistence().extensionData();
            String valid = RunHistoryCodec.encode(List.of(run(1).snapshot()));
            for (String source : List.of("{\"version\":99}\nfuture", "broken", valid.replace("RUNNING", "PAUSED"), valid + "\n")) {
                fake.persisted.put(PersistedState.K_RUN_HISTORY, source);
                assertFalse(PersistedState.loadRunHistory(store).writable());
                assertFalse(PersistedState.saveRunHistory(store, List.of())); assertEquals(source, fake.persisted.get(PersistedState.K_RUN_HISTORY));
            }
            PersistedState.resetRunHistory(store); assertTrue(PersistedState.saveRunHistory(store, List.of()));
        }
    }

    @Test public void comparisonUsesStableFindingIdentityAndLateEventsKeepRunId() {
        var old = run(1); var next = run(1); var history = new RunHistory(); history.register(old); history.register(next);
        var sample = ActiveEvidenceCodecTest.sample(VerificationState.CANDIDATE);
        var first = evidenceInRun(sample, old, "https://api.example.test/search?q=old");
        var repeat = evidenceInRun(sample, next, "https://api.example.test/search?q=new");
        history.finding(first); history.finding(repeat);
        var fresh = new ReconModel.ActiveRow(repeat.severity(), "new-detector", repeat.parameter(), repeat.status(), repeat.evidence(), repeat.url(),
                withRun(FindingEvidence.metadata("new-detector", VerificationState.SIGNAL, "lead"), next.id().toString()));
        history.finding(fresh); old.complete(); next.complete();
        var diff = history.diff(old.id().toString(), next.id().toString()); assertEquals(1, diff.shared().size()); assertEquals(1, diff.added().size()); assertTrue(diff.notObserved().isEmpty());
        var restored = new RunHistory(); restored.restore(RunHistoryCodec.decode(RunHistoryCodec.encode(history.snapshot())).runs());
        restored.finding(repeat.withEvidence(withRun(FindingEvidence.metadata("later", VerificationState.CONFIRMED, "late callback"), next.id().toString())));
        assertEquals(3, restored.get(next.id().toString()).findings().size());
        assertEquals(RunStatus.COMPLETED, restored.get(next.id().toString()).status());
    }
    static ReconModel.ActiveRow evidenceInRun(ReconModel.ActiveRow row, ScanRun run, String url) {
        return new ReconModel.ActiveRow(row.severity(), row.testClass(), row.parameter(), row.status(), row.evidence(), url, withRun(row.evidenceRecord(), run.id().toString()));
    }
    static FindingEvidence withRun(FindingEvidence e, String id) {
        return new FindingEvidence(e.id(), e.captureId(), id, e.source(), e.detectorId(), e.detectorVersion(), e.state(), e.observedAt(), e.rationale(), e.reproduction(),
                e.originalRequest(), e.originalResponse(), e.exchanges(), e.attempted(), e.omittedExchanges(), e.issuedTokens(), e.observation(), e.relatedEvidenceIds());
    }
}
