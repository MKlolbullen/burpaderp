package com.victor.reconloop;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.util.List;

/** History and controls operate on stable run IDs, never table positions. */
final class RunHistoryPanel extends JPanel {
    private final ReconController controller;
    private final RunTable model = new RunTable();
    private final JTable runs = new JTable(model);
    private final JComboBox<String> baseline = new JComboBox<>();
    private final JCheckBox newOnly = new JCheckBox("Show new findings only");
    private final JLabel result = new JLabel("Select a run. In-flight requests can finish after pause/cancel.");
    private final JTextArea details = new JTextArea();
    private final TableRowSorter<ReconModel.ActiveTableModel> findingsSorter;
    private final ReconModel.ActiveTableModel findings;
    private final TableRowSorter<ReconModel.FindingTableModel> passiveSorter;
    private final ReconModel.FindingTableModel passive;
    private final Timer refresh;

    RunHistoryPanel(ReconController controller, JTable findingsTable, ReconModel.ActiveTableModel findings, JTable passiveTable, ReconModel.FindingTableModel passive) {
        super(new BorderLayout(8, 8)); this.controller = controller; this.findings = findings; this.passive = passive;
        passiveSorter = new TableRowSorter<>(passive); passiveTable.setRowSorter(passiveSorter);
        findingsSorter = new TableRowSorter<>(findings); findingsTable.setRowSorter(findingsSorter);
        runs.setAutoCreateRowSorter(true); runs.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        details.setEditable(false); details.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        var split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(runs), new JScrollPane(details)); split.setResizeWeight(.45);
        add(split, BorderLayout.CENTER);
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        for (String action : List.of("Pause", "Resume", "Cancel")) {
            JButton button = new JButton(action); actions.add(button);
            button.addActionListener(e -> {
                String id = selected();
                result.setText(id != null && controller.controlRun(id, action.toLowerCase(java.util.Locale.ROOT))
                        ? action + " applied to " + id : "This control is unavailable for the selected run."); refresh();
            });
        }
        JButton retry = new JButton("Re-run failed / inconclusive probes"); actions.add(retry);
        retry.setToolTipText("Creates a child run using current in-scope site-map messages, quotas and explicit risk grants. Native and corpus probes only.");
        retry.addActionListener(e -> {
            String id = selected(); result.setText(id != null && controller.retryFailedProbes(id)
                    ? "Retry queued with current scope and grants. Check the child run and extension log."
                    : "No eligible native/corpus probes, or active testing is disabled.");
        });
        JButton compare = new JButton("Compare"); actions.add(new JLabel("Baseline:")); actions.add(baseline); actions.add(compare); actions.add(newOnly);
        compare.addActionListener(e -> compare()); newOnly.addActionListener(e -> filter()); baseline.addActionListener(e -> filter());
        JPanel footer = new JPanel(new BorderLayout()); footer.add(actions, BorderLayout.CENTER); footer.add(result, BorderLayout.SOUTH); add(footer, BorderLayout.SOUTH);
        runs.getSelectionModel().addListSelectionListener(e -> { if (!e.getValueIsAdjusting()) { showDetails(); filter(); } });
        findings.addTableModelListener(e -> filter());
        passive.addTableModelListener(e -> filter());
        refresh = new Timer(1000, e -> refresh()); refresh();
    }
    @Override public void addNotify() { super.addNotify(); refresh.start(); }
    @Override public void removeNotify() { refresh.stop(); super.removeNotify(); }
    private String selected() { int index = runs.getSelectedRow(); return index < 0 ? null : model.rows.get(runs.convertRowIndexToModel(index)).id(); }
    private void refresh() {
        String id = selected(), oldBaseline = (String)baseline.getSelectedItem();
        var rows = controller.runHistory().snapshot();
        model.rows = rows; model.fireTableDataChanged();
        baseline.removeAllItems(); for (var row : rows) baseline.addItem(row.id());
        if (oldBaseline != null) baseline.setSelectedItem(oldBaseline);
        if (id != null) for (int i = 0; i < rows.size(); i++) if (rows.get(i).id().equals(id)) {
            int view = runs.convertRowIndexToView(i); if (view >= 0) runs.setRowSelectionInterval(view, view); break;
        }
        showDetails(); filter();
    }
    private void showDetails() {
        var run = controller.runHistory().get(selected() == null ? "" : selected());
        if (run == null) { details.setText(""); return; }
        int caret = details.getCaretPosition();
        details.setText("Run: " + run.id() + "\nParent: " + run.parentId() + "\nProfile: " + run.profile() + "\nScope snapshot: " + run.scope()
                + "\nQuotas: " + run.limits() + "\nMetrics: " + run.metrics() + "\nOutstanding dispatch results: " + run.metrics().inFlight() + "\nOmitted audit/probe/finding records: "
                + run.omittedEvents() + "/" + run.omittedProbes() + "/" + run.omittedFindings()
                + "\nHistory contains hashes; captured HTTP bodies remain in finding evidence.\n\n" + Json.write(RunHistoryCodec.map(run)));
        details.setCaretPosition(Math.min(caret, details.getDocument().getLength()));
    }
    private void compare() {
        String id = selected(), old = (String)baseline.getSelectedItem(); if (id == null || old == null) return;
        var diff = controller.runHistory().diff(old, id);
        result.setText("New: " + diff.added().size() + " | Shared: " + diff.shared().size() + " | Not observed: " + diff.notObserved().size()
                + (diff.complete() ? "" : " | Partial retained finding index") + ". Not observed does not establish resolution."); filter();
    }
    private void filter() {
        String selected = selected(), old = (String)baseline.getSelectedItem();
        if (!newOnly.isSelected()) { findingsSorter.setRowFilter(null); passiveSorter.setRowFilter(null); return; }
        var keys = controller.runHistory().diff(old == null ? "" : old, selected == null ? "" : selected).added();
        passiveSorter.setRowFilter(new RowFilter<>() {
            @Override public boolean include(Entry<? extends ReconModel.FindingTableModel, ? extends Integer> entry) {
                var row = passive.snapshot().get(entry.getIdentifier());
                return row.runId().equals(selected) && keys.contains(RunRecord.passiveFinding(row).key());
            }
        });
        findingsSorter.setRowFilter(new RowFilter<>() {
            @Override public boolean include(Entry<? extends ReconModel.ActiveTableModel, ? extends Integer> entry) {
                var row = findings.row(entry.getIdentifier());
                return row.evidenceRecord().runId().equals(selected) && keys.contains(RunRecord.findingKey(row));
            }
        });
    }
    private static final class RunTable extends AbstractTableModel {
        List<RunRecord> rows = List.of();
        private final String[] columns = {"Run ID", "Status", "Profile", "Started", "Admitted / cap", "Sent", "Responses", "Errors", "Denied", "Findings"};
        public int getRowCount() { return rows.size(); } public int getColumnCount() { return columns.length; }
        public String getColumnName(int c) { return columns[c]; }
        public Object getValueAt(int i, int c) { var r = rows.get(i); var m = r.metrics(); return switch(c) {
            case 0 -> r.id(); case 1 -> r.status(); case 2 -> r.profile(); case 3 -> r.startedAt();
            case 4 -> m.admitted() + " / " + r.limits().global(); case 5 -> m.dispatched(); case 6 -> m.responses();
            case 7 -> m.errors(); case 8 -> m.denied(); default -> r.findingKeys().size();
        }; }
    }
}
