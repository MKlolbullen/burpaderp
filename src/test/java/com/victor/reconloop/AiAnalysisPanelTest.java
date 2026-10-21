package com.victor.reconloop;

import org.junit.Test;
import javax.swing.SwingUtilities;
import java.util.List;
import java.util.concurrent.FutureTask;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import static org.junit.Assert.*;

public class AiAnalysisPanelTest {
    private static final List<LlmClient.LlmCredential> CREDS = List.of(
            new LlmClient.LlmCredential(LlmProvider.OPENAI, "test-model", "FAKE-ONLY"),
            new LlmClient.LlmCredential(LlmProvider.VENICE, "test-model-2", "FAKE-ONLY-2"));

    @Test public void stagingAndPreviewNeverCallProvidersAndPreviewHidesKeys() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AiAnalysisPanel panel = new AiAnalysisPanel(() -> CREDS, (c, s, r, d) -> { fail("No automatic send"); return null; });
            panel.stage(AiAnalysis.Kind.HTTP_EXCHANGE, "exchange", "Authorization: Bearer STAGED-SECRET\nbody");
            assertFalse(panel.send.isEnabled()); panel.prepare.doClick(); assertTrue(panel.send.isEnabled());
            String preview = panel.preview.getText(); assertTrue(preview.contains("OpenAI / test-model"));
            assertTrue(preview.contains("Venice.ai / test-model-2")); assertTrue(preview.contains("[REDACTED]"));
            assertFalse(preview.contains("STAGED-SECRET")); assertFalse(preview.contains("FAKE-ONLY"));
        });
    }

    @Test public void editingFocusSourceOrCredentialsInvalidatesThePreparedUpload() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AiAnalysisPanel(() -> CREDS, (c, s, r, d) -> { fail(); return null; });
            panel.stage(AiAnalysis.Kind.TEXT, "text", "original text"); panel.preparePreview();
            panel.editor.append(" edit"); assertFalse(panel.send.isEnabled());
            panel.preparePreview(); panel.focus.setText("SSRF"); assertFalse(panel.send.isEnabled());
            panel.preparePreview(); panel.credentialsChanged(); assertFalse(panel.send.isEnabled());
            panel.startReview(); // invalidated snapshot cannot be sent programmatically either
        });
    }

    @Test public void explicitSendUsesThePreviewedSnapshotAndCancellationIgnoresLateCallbacks() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AtomicReference<Consumer<AiAnalysis.ProviderReport>> callback = new AtomicReference<>();
            AtomicReference<Runnable> done = new AtomicReference<>();
            AtomicReference<AiAnalysis.Snapshot> sent = new AtomicReference<>(); AtomicInteger calls = new AtomicInteger();
            var task = new FutureTask<Void>(() -> null);
            var panel = new AiAnalysisPanel(() -> CREDS, (c, s, r, d) -> {
                calls.incrementAndGet(); assertEquals(CREDS, c); sent.set(s); callback.set(r); done.set(d); return task;
            });
            panel.stage(AiAnalysis.Kind.JAVASCRIPT, "app.js", "el.innerHTML = location.hash;");
            panel.preparePreview(); String preview = panel.preview.getText(); panel.send.doClick();
            assertEquals(1, calls.get()); assertTrue(preview.endsWith(sent.get().prompt())); assertFalse(panel.editor.isEditable());
            panel.send.doClick(); assertEquals(1, calls.get());
            panel.cancel.doClick(); assertTrue(task.isCancelled()); assertTrue(panel.editor.isEditable());
            callback.get().accept(new AiAnalysis.ProviderReport(LlmProvider.OPENAI, "m",
                    AiAnalysis.parse(AiAnalysisTest.response(AiAnalysisTest.finding("s1", "innerHTML")), sent.get())));
            done.get().run(); assertEquals("", panel.results.getText());
        });
    }

    @Test public void completedResultsAreCandidatesAndCannotBeResentWithoutANewPreview() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AtomicReference<Runnable> done = new AtomicReference<>();
            var panel = new AiAnalysisPanel(() -> CREDS, (c, s, r, d) -> {
                r.accept(new AiAnalysis.ProviderReport(LlmProvider.OPENAI, "m",
                        AiAnalysis.parse(AiAnalysisTest.response(AiAnalysisTest.finding("s1", "innerHTML")), s)));
                done.set(d); return new FutureTask<Void>(() -> null);
            });
            panel.stage(AiAnalysis.Kind.JAVASCRIPT, "app.js", "el.innerHTML = location.hash;");
            panel.preparePreview(); panel.startReview(); done.get().run();
            assertTrue(panel.results.getText().contains("CANDIDATE")); assertFalse(panel.send.isEnabled()); assertTrue(panel.prepare.isEnabled());
        });
    }

    @Test public void missingCredentialsOrOversizedSelectionsCannotPrepareAnUpload() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new AiAnalysisPanel(List::of, (c, s, r, d) -> { fail(); return null; });
            panel.stage(AiAnalysis.Kind.TEXT, "text", "some text"); panel.preparePreview(); assertFalse(panel.send.isEnabled());
            assertThrows(IllegalArgumentException.class, () -> panel.stage(AiAnalysis.Kind.TEXT, "big", "x".repeat(48_001)));
        });
    }
}
