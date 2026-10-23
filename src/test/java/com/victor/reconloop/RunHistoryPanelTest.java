package com.victor.reconloop;

import org.junit.Test;
import javax.swing.*;
import java.awt.*;
import java.util.*;
import java.util.List;
import static org.junit.Assert.*;

public class RunHistoryPanelTest {
    @Test public void controlsUseSelectedRunIdAndNewOnlyFiltersBothFindingTables() throws Exception {
        try (var fake = new FakeMontoya()) {
            var controller = ReconControllerRunLifecycleTest.controller(fake, new ManualExecutor());
            try {
                SwingUtilities.invokeAndWait(() -> {
                    var history = controller.runHistory();
                    var old = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2);
                    var next = ScanRun.begin(ScanProfile.ACTIVE_SAFE, ScopeSnapshot.empty(), 2); history.register(old); history.register(next);
                    var active = new ReconModel.ActiveTableModel(); var passive = new ReconModel.FindingTableModel();
                    var sample = ActiveEvidenceCodecTest.sample(VerificationState.CANDIDATE);
                    var previous = RunHistoryIntegrationTest.evidenceInRun(sample, old, "https://api.example.test/search?q=old");
                    var repeat = RunHistoryIntegrationTest.evidenceInRun(sample, next, "https://api.example.test/search?q=new");
                    active.add(previous); history.finding(previous); active.add(repeat); history.finding(repeat);
                    var added = new ReconModel.ActiveRow("LOW", "new", "point", "candidate", "new lead", repeat.url(),
                            RunHistoryIntegrationTest.withRun(FindingEvidence.metadata("new", VerificationState.CANDIDATE, "lead"), next.id().toString()));
                    active.add(added); history.finding(added);
                    var passiveOld = new ReconModel.FindingRow("INFO", "p", "old", "response", "value", repeat.url()).withRun(old.id().toString());
                    var passiveNew = new ReconModel.FindingRow("INFO", "p", "new", "response", "value", repeat.url()).withRun(next.id().toString());
                    passive.add(passiveOld); history.finding(passiveOld); passive.add(passiveNew); history.finding(passiveNew);
                    JTable activeTable = new JTable(active), passiveTable = new JTable(passive);
                    var panel = new RunHistoryPanel(controller, activeTable, active, passiveTable, passive);
                    var components = descendants(panel);
                    JTable runs = components.stream().filter(JTable.class::isInstance).map(JTable.class::cast).findFirst().orElseThrow();
                    int selected = -1; for (int i = 0; i < runs.getRowCount(); i++) if (next.id().toString().equals(runs.getValueAt(i, 0))) selected = i;
                    runs.setRowSelectionInterval(selected, selected);
                    button(components, "Pause").doClick(); assertEquals(RunStatus.PAUSED, next.status()); assertEquals(RunStatus.RUNNING, old.status());
                    button(components, "Resume").doClick(); assertEquals(RunStatus.RUNNING, next.status());
                    @SuppressWarnings("unchecked") JComboBox<String> baseline = (JComboBox<String>)components.stream().filter(JComboBox.class::isInstance).findFirst().orElseThrow();
                    baseline.setSelectedItem(old.id().toString());
                    var check = components.stream().filter(JCheckBox.class::isInstance).map(JCheckBox.class::cast).findFirst().orElseThrow(); check.doClick();
                    assertEquals(1, activeTable.getRowCount()); assertEquals("new", activeTable.getValueAt(0, 1));
                    assertEquals(1, passiveTable.getRowCount()); assertEquals("new", passiveTable.getValueAt(0, 2));
                    check.doClick(); assertEquals(3, activeTable.getRowCount()); assertEquals(2, passiveTable.getRowCount());
                    button(components, "Cancel").doClick(); assertEquals(RunStatus.CANCELLED, next.status());
                    assertTrue(fake.sent.isEmpty());
                });
            } finally { controller.shutdown(); }
        }
    }
    private static JButton button(List<Component> components, String text) {
        return components.stream().filter(JButton.class::isInstance).map(JButton.class::cast).filter(b -> b.getText().equals(text)).findFirst().orElseThrow();
    }
    private static List<Component> descendants(Container parent) {
        var result = new ArrayList<Component>();
        for (var component : parent.getComponents()) { result.add(component); if (component instanceof Container child) result.addAll(descendants(child)); }
        return result;
    }
}
