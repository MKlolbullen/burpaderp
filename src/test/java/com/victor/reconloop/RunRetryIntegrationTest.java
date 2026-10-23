package com.victor.reconloop;

import org.junit.Test;
import javax.swing.SwingUtilities;
import java.util.*;
import static org.junit.Assert.*;

public class RunRetryIntegrationTest {
    private static final String URL = "https://api.example.test/search?q=a";

    @Test public void failedNativeProbeRetriesInAChildRunUsingCurrentSessionAndCurrentQuotas() throws Exception {
        try (var fake = new FakeMontoya()) {
            var executor = new ManualExecutor(); var controller = ReconControllerRunLifecycleTest.controller(fake, executor);
            try {
                var old = fake.request(URL).withHeader("Authorization", "Bearer old-session");
                fake.siteMap.add(FakeMontoya.pair(old, FakeMontoya.response(200, "", Map.of())));
                fake.onSend = ignored -> { throw new IllegalStateException("transport unavailable"); };
                controller.setActiveTestsEnabled(true); controller.setActiveRequestBudget(2);
                controller.runActiveTests(); executor.runAll();
                var first = controller.runHistory().snapshot().getFirst();
                assertEquals(RunStatus.COMPLETED, first.status()); assertEquals(2, first.metrics().errors());
                var eligible = controller.runHistory().retries(first.id()); assertFalse(eligible.isEmpty());
                fake.siteMap.clear(); var current = fake.request(URL).withHeader("Authorization", "Bearer refreshed-session");
                fake.siteMap.add(FakeMontoya.pair(current, FakeMontoya.response(200, "", Map.of())));
                fake.onSend = ignored -> {}; int before = fake.sent.size();
                controller.setActiveRequestBudget(1); assertTrue(controller.retryFailedProbes(first.id())); executor.runAll();
                var child = controller.runHistory().snapshot().stream().filter(r -> r.parentId().equals(first.id())).findFirst().orElseThrow();
                assertNotEquals(first.id(), child.id()); assertEquals(1, child.metrics().admitted()); assertEquals(1, child.limits().global());
                assertEquals(Set.of("api.example.test"), child.scope().domains()); assertEquals(before + 1, fake.sent.size());
                assertEquals("Bearer refreshed-session", fake.sent.getLast().headerValue("Authorization"));
                Set<String> eligibleIds = new HashSet<>(); eligible.forEach(p -> eligibleIds.add(p.probe()));
                assertTrue(child.audit().stream().filter(e -> e.kind().equals("REQUEST")).allMatch(e -> eligibleIds.contains(e.probe())));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void retryDoesNotSendWhenScopeIsRevokedAndQueuedRetryCannotSurvivePermissionChanges() throws Exception {
        try (var fake = new FakeMontoya()) {
            var executor = new ManualExecutor(); var controller = ReconControllerRunLifecycleTest.controller(fake, executor);
            try {
                fake.siteMap.add(FakeMontoya.pair(fake.request(URL), FakeMontoya.response(200, "", Map.of())));
                fake.onSend = ignored -> { throw new IllegalStateException("offline"); };
                controller.setActiveTestsEnabled(true); controller.setActiveRequestBudget(1);
                controller.runActiveTests(); executor.runAll(); var parent = controller.runHistory().snapshot().getFirst();
                int sent = fake.sent.size(); fake.inScope = ignored -> false;
                assertTrue(controller.retryFailedProbes(parent.id())); executor.runAll(); assertEquals(sent, fake.sent.size());
                fake.inScope = ignored -> true; assertTrue(controller.retryFailedProbes(parent.id()));
                controller.setOastActiveRequests(true); controller.setOastActiveRequests(false);
                executor.runAll(); assertEquals(sent, fake.sent.size());
                controller.setActiveTestsEnabled(false); assertFalse(controller.retryFailedProbes(parent.id()));
            } finally { controller.shutdown(); }
        }
    }

    @Test public void restoredHistoryDoesNotSendOrRestoreAuthorizationAndCanBeRetriedExplicitly() throws Exception {
        try (var fake = new FakeMontoya()) {
            var executor = new ManualExecutor(); var first = ReconControllerRunLifecycleTest.controller(fake, executor);
            fake.siteMap.add(FakeMontoya.pair(fake.request(URL), FakeMontoya.response(200, "", Map.of())));
            fake.onSend = ignored -> { throw new IllegalStateException("offline"); };
            first.setActiveTestsEnabled(true); first.setActiveRequestBudget(1); first.runActiveTests(); executor.runAll();
            var record = first.runHistory().snapshot().getFirst(); first.shutdown();
            assertTrue(fake.persisted.containsKey(PersistedState.K_RUN_HISTORY)); int sent = fake.sent.size();
            var restoredExecutor = new ManualExecutor(); var restored = ReconControllerRunLifecycleTest.controller(fake, restoredExecutor);
            try {
                SwingUtilities.invokeAndWait(() -> {}); restoredExecutor.runAll();
                assertEquals(sent, fake.sent.size()); assertEquals(record.id(), restored.runHistory().snapshot().getFirst().id());
                assertFalse(restored.controlRun(record.id(), "resume")); assertFalse(restored.retryFailedProbes(record.id()));
                restored.setActiveTestsEnabled(true); restored.setActiveRequestBudget(1);
                fake.onSend = ignored -> {}; assertTrue(restored.retryFailedProbes(record.id())); restoredExecutor.runAll();
                assertEquals(sent + 1, fake.sent.size()); assertTrue(restored.runHistory().snapshot().stream().anyMatch(r -> r.parentId().equals(record.id())));
            } finally { restored.shutdown(); }
        }
    }

    @Test public void corpusRetryRestrictsCategoryParameterAndEncodingAndKeepsRiskGates() {
        try (var fake = new FakeMontoya()) {
            var base = fake.request(URL); var parent = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.forTargetUrl(URL), 1);
            var target = RunRecord.target(base.method(), base.url());
            String parameter = FindingEvidence.digest(base.parameters().getFirst().type() + "\0" + base.parameters().getFirst().name());
            var probe = new RunRecord.Probe(RunRecord.probeKey("CORPUS", "corpus-fuzz:sqli", target, parameter, "RAW"), "CORPUS", "corpus-fuzz:sqli", target, parameter, "RAW", 1, RunRecord.ProbeStatus.FAILED);
            parent.probe(probe); parent.complete();
            var plan = RunRetry.plan(parent.id().toString(), List.of(probe), List.of(base), ignored -> true);
            var child = ScanRun.begin(ScanProfile.ACTIVE_SAFE, plan.scope(), 3); child.parent(parent.id().toString());
            RunRetry.execute(plan, child, new ActiveRequestGateway(RequestPolicy.safeDefault(ignored -> true), fake.transport()),
                    new ActiveTestEngine(fake.api, 0), new CorpusFuzzEngine(fake.api, new PayloadLibrary(), 0), (f, r) -> {});
            assertEquals(1, fake.sent.size()); assertEquals(1, child.probeRequests("corpus-fuzz:sqli"));
            assertEquals(1, child.snapshot().probes().size()); assertEquals("RAW", child.snapshot().probes().getFirst().encoding());
        }
    }
}
