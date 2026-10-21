package com.victor.reconloop;

import org.junit.Test;
import javax.swing.*;
import java.awt.*;
import java.util.concurrent.Executors;
import static org.junit.Assert.*;

public class ReconPanelAiLayoutTest {
    private static <T> T find(Component component, Class<T> type, java.util.function.Predicate<T> predicate) {
        if (type.isInstance(component) && predicate.test(type.cast(component))) return type.cast(component);
        if (component instanceof Container container) for (Component child : container.getComponents()) {
            T found = find(child, type, predicate); if (found != null) return found;
        }
        return null;
    }
    private static void layout(Component component) {
        if (component instanceof Container container) {
            container.doLayout(); for (Component child : container.getComponents()) layout(child);
        }
    }

    @Test public void evidenceWorkspaceHasUsableSpaceAndScanControlsCanBeReopened() throws Exception {
        try (var fake = new FakeMontoya()) {
            var f = new ReconModel.FindingTableModel(); var d = new ReconModel.DiscoveryTableModel();
            var p = new ReconModel.ParameterTableModel(); var r = new ReconModel.ReflectionTableModel();
            var a = new ReconModel.ActiveTableModel(); var assets = new ReconModel.AssetTableModel();
            var controller = new ReconController(fake.api, f, d, p, r, a, assets, Executors.newSingleThreadExecutor(),
                    false, fake.destinations(), new LlmClient(request -> { fail("Layout must not send"); return null; }));
            try {
                SwingUtilities.invokeAndWait(() -> {
                    var panel = new ReconPanel(fake.api, controller, f, d, p, r, a, assets); panel.setSize(1280, 900);
                    var tabs = find(panel, JTabbedPane.class, t -> t.indexOfTab("AI analysis") >= 0);
                    tabs.setSelectedIndex(tabs.indexOfTab("AI analysis")); layout(panel);
                    var review = find(panel, AiAnalysisPanel.class, v -> true);
                    assertTrue("Evidence workspace must remain visible below provider controls", review.getHeight() >= 350);
                    var toggle = find(panel, JToggleButton.class, b -> b.getText().equals("Show scan controls"));
                    assertNotNull(toggle); toggle.doClick(); assertEquals("Hide scan controls", toggle.getText());
                    toggle.doClick(); assertEquals("Show scan controls", toggle.getText());
                    for (var provider : LlmProvider.values()) {
                        var checkbox = find(panel, JCheckBox.class, box -> box.getText().equals(provider.label()));
                        checkbox.doClick();
                    }
                    fillKeys(panel);
                    review.stage(AiAnalysis.Kind.JAVASCRIPT, "app.js", "el.innerHTML = location.hash;");
                    var planner = find(panel, JButton.class, b -> b.getText().equals("Plan agent jobs…")); planner.doClick(); layout(panel);
                    var team = find(panel, EvidenceAgentPanel.class, v -> true);
                    assertTrue(team.run.isEnabled()); assertTrue("Agent job workspace must remain usable", team.getHeight() >= 450);
                    review.editor.append(" // evidence changed"); assertFalse("Changed evidence must invalidate the team plan", team.run.isEnabled());
                });
                assertTrue(fake.sent.isEmpty()); assertTrue(fake.issues.isEmpty());
            } finally { controller.shutdown(); }
        }
    }
    private static void fillKeys(Component component) {
        if (component instanceof JPasswordField password) password.setText("FAKE-ONLY");
        if (component instanceof Container container) for (var child : container.getComponents()) fillKeys(child);
    }
}
