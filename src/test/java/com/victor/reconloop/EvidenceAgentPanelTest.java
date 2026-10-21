package com.victor.reconloop;

import org.junit.Test;
import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import static org.junit.Assert.*;

public class EvidenceAgentPanelTest {
    static List<LlmClient.LlmCredential> credentials() { return EvidenceAgentJobsTest.bindings(1).stream().map(EvidenceAgentJobs.Binding::credential).toList(); }
    @Test public void rosterAndPlanPreviewDoNotCallProvidersAndExplainAllFiveJobs() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new EvidenceAgentPanel(AiAnalysisTest::snapshot, EvidenceAgentPanelTest::credentials, (p, e, d) -> { fail("Preview cannot dispatch"); return null; });
            assertEquals(5, panel.rows.size()); assertFalse(panel.run.isEnabled());
            panel.preparePlan(); assertTrue(panel.run.isEnabled()); assertEquals(5, panel.jobs.getRowCount());
            assertTrue(panel.preview.getText().contains("Maximum provider calls: 10")); assertFalse(panel.preview.getText().contains("FAKE-PRIVATE-KEY"));
        });
    }
    @Test public void evidenceProviderAndBudgetEditsInvalidateThePlan() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new EvidenceAgentPanel(AiAnalysisTest::snapshot, EvidenceAgentPanelTest::credentials, (p, e, d) -> { fail(); return null; });
            panel.preparePlan(); panel.rows.getFirst().tools().setValue(2); assertFalse(panel.run.isEnabled());
            panel.preparePlan(); panel.rows.getFirst().provider().setSelectedItem(LlmProvider.OPENAI); assertFalse(panel.run.isEnabled());
            panel.preparePlan(); panel.contextChanged(); assertFalse(panel.run.isEnabled()); panel.start();
        });
    }
    @Test public void explicitRunUsesFrozenPlanAndCancellationIgnoresLateEvents() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AtomicReference<EvidenceAgentJobs.Plan> sent = new AtomicReference<>();
            AtomicReference<Consumer<EvidenceAgentRunner.Event>> event = new AtomicReference<>();
            AtomicReference<Consumer<EvidenceAgentRunner.Outcome>> done = new AtomicReference<>();
            AtomicInteger calls = new AtomicInteger(); var future = new FutureTask<Void>(() -> null);
            var panel = new EvidenceAgentPanel(AiAnalysisTest::snapshot, EvidenceAgentPanelTest::credentials, (p, e, d) -> {
                sent.set(p); event.set(e); done.set(d); calls.incrementAndGet(); return future;
            });
            panel.preparePlan(); String preview = panel.preview.getText(); panel.run.doClick();
            assertEquals(1, calls.get()); assertTrue(preview.endsWith(sent.get().snapshot().prompt()));
            assertFalse(panel.rows.getFirst().provider().isEnabled()); panel.run.doClick(); assertEquals(1, calls.get());
            panel.cancel.doClick(); assertTrue(future.isCancelled()); assertFalse(panel.run.isEnabled());
            event.get().accept(new EvidenceAgentRunner.Event("surface", AgentRole.RECON, LlmProvider.GEMINI, "m", EvidenceAgentRunner.State.COMPLETED, 1, 0, "Late"));
            done.get().accept(new EvidenceAgentRunner.Outcome(sent.get().runId(), EvidenceAgentRunner.State.COMPLETED, List.of(), List.of()));
            assertEquals("CANCELLED", panel.jobs.getValueAt(0, 3)); assertEquals("", panel.report.getText());
        });
    }
    @Test public void completionDisplaysTheReportAndRequiresANewPlanBeforeRerun() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AtomicReference<Runnable> done = new AtomicReference<>();
            var panel = new EvidenceAgentPanel(AiAnalysisTest::snapshot, EvidenceAgentPanelTest::credentials, (p, e, d) -> {
                var outcome = new EvidenceAgentRunner((c, s, prompt, t) -> EvidenceAgentRunnerTest.valid(prompt)).run(p, e, () -> false);
                done.set(() -> d.accept(outcome)); return new FutureTask<Void>(() -> null);
            });
            panel.preparePlan(); panel.start(); done.get().run();
            assertTrue(panel.report.getText().contains("CANDIDATE")); assertFalse(panel.run.isEnabled()); assertTrue(panel.prepare.isEnabled());
            assertEquals("COMPLETED", panel.jobs.getValueAt(4, 3));
        });
    }
    @Test public void missingCredentialsAndNonIndependentReviewerCannotPrepare() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var missing = new EvidenceAgentPanel(AiAnalysisTest::snapshot, List::of, (p, e, d) -> { fail(); return null; });
            missing.preparePlan(); assertFalse(missing.run.isEnabled());
            var invalid = new EvidenceAgentPanel(AiAnalysisTest::snapshot, EvidenceAgentPanelTest::credentials, (p, e, d) -> { fail(); return null; });
            invalid.rows.get(3).provider().setSelectedItem(LlmProvider.OPENAI); invalid.preparePlan(); assertFalse(invalid.run.isEnabled());
        });
    }
}
