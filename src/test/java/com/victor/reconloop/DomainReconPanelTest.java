package com.victor.reconloop;

import org.junit.Test;
import javax.swing.*;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import static org.junit.Assert.*;

public class DomainReconPanelTest {
    @Test public void previewRunsNothingAndChangesInvalidatePlan() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            var panel = new DomainReconPanel((plan,events,done) -> { fail("preview launched process");return null; }, (path, done) -> fail("preview imported"));
            panel.target.setText("https://example.com"); panel.output.setText(Path.of("output").toAbsolutePath().toString()); panel.preparePlan();
            assertFalse(panel.start.isEnabled());
            panel.target.setText("example.com"); panel.preparePlan();
            assertTrue(panel.start.isEnabled()); assertTrue(panel.savePlan.isEnabled()); assertTrue(panel.preview.getText().contains("BLOCKED")); assertTrue(panel.chain.getRowCount()>14);
            panel.hosts.setValue(10); assertFalse(panel.start.isEnabled()); assertFalse(panel.savePlan.isEnabled());
        });
    }
    @Test public void cancelRestoresFormAndIgnoresStaleEventsAndCompletion() throws Exception {
        SwingUtilities.invokeAndWait(() -> {
            AtomicReference<Consumer<DomainReconProcess.Event>> events = new AtomicReference<>();
            AtomicReference<Consumer<DomainReconProcess.Outcome>> done = new AtomicReference<>();
            CompletableFuture<Void> task = new CompletableFuture<>();
            var panel = new DomainReconPanel((plan, listener, complete) -> { events.set(listener);done.set(complete); return task; }, (path, callback) -> fail("auto import"));
            panel.target.setText("example.com"); panel.output.setText("output"); panel.preparePlan(); panel.start();
            assertFalse(panel.target.isEnabled()); assertTrue(panel.cancel.isEnabled());
            panel.cancel(); assertTrue(task.isCancelled()); assertTrue(panel.target.isEnabled()); assertFalse(panel.start.isEnabled());
            events.get().accept(new DomainReconProcess.Event("host","assetfinder","","stale.example.com",1,""));
            done.get().accept(new DomainReconProcess.Outcome("SUCCESS",1,"late"));
            assertEquals(0,panel.results.getRowCount()); assertFalse(panel.importHosts.isEnabled()); assertTrue(panel.status.getText().contains("Cancellation requested"));
        });
    }
}
