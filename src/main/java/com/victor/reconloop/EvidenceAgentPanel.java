package com.victor.reconloop;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Five configurable agents, reviewable job plan, live states and a session-only report. */
final class EvidenceAgentPanel extends JPanel {
    @FunctionalInterface interface Runner {
        Future<?> run(EvidenceAgentJobs.Plan plan, Consumer<EvidenceAgentRunner.Event> events, Consumer<EvidenceAgentRunner.Outcome> done);
    }
    record Row(EvidenceAgentJobs.Job job, JComboBox<LlmProvider> provider, JSpinner output, JSpinner tools) {}
    final List<Row> rows = new ArrayList<>();
    final JButton prepare = new JButton("Preview five-agent jobs");
    final JButton run = new JButton("Run previewed jobs");
    final JButton cancel = new JButton("Cancel jobs");
    final JTextArea preview = text(), report = text();
    final DefaultTableModel jobs = new DefaultTableModel(new String[]{"Job", "Role", "Provider / model", "State", "Calls", "Tools", "Detail"}, 0) {
        @Override public boolean isCellEditable(int row, int column) { return false; }
    };
    private final JLabel status = new JLabel("Select evidence and enable providers in AI analysis, then preview the five jobs.");
    private final JTabbedPane views = new JTabbedPane();
    private final Supplier<AiAnalysis.Snapshot> evidence;
    private final Supplier<List<LlmClient.LlmCredential>> credentials;
    private final Runner runner;
    private EvidenceAgentJobs.Plan prepared;
    private Future<?> running;
    private long generation;

    EvidenceAgentPanel(Supplier<AiAnalysis.Snapshot> evidence, Supplier<List<LlmClient.LlmCredential>> credentials, Runner runner) {
        super(new BorderLayout(4, 4)); this.evidence = evidence; this.credentials = credentials; this.runner = runner;
        JPanel roster = new JPanel(new GridLayout(0, 4, 4, 2));
        for (String header : List.of("Agent / job", "Provider (model/key from AI analysis)", "Output tokens per call", "Local tool calls")) roster.add(new JLabel(header));
        for (var job : EvidenceAgentJobs.JOBS) {
            JComboBox<LlmProvider> provider = new JComboBox<>(LlmProvider.values());
            provider.setRenderer(new DefaultListCellRenderer() {
                @Override public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
                    return super.getListCellRendererComponent(list, value instanceof LlmProvider p ? p.label() : value, index, selected, focus);
                }
            });
            provider.setSelectedItem(job.role().defaultProvider());
            JSpinner output = new JSpinner(new SpinnerNumberModel(4096, 256, 8192, 256));
            JSpinner tools = new JSpinner(new SpinnerNumberModel(1, 0, 2, 1));
            JLabel role = new JLabel(job.id() + " · " + job.role().title());
            role.setToolTipText(job.skills().stream().map(s -> s.id() + ": " + s.instructions()).reduce("", (a, b) -> a + " " + b));
            roster.add(role); roster.add(provider); roster.add(output); roster.add(tools);
            rows.add(new Row(job, provider, output, tools));
            provider.addActionListener(e -> contextChanged());
            ChangeListener changed = e -> contextChanged(); output.addChangeListener(changed); tools.addChangeListener(changed);
        }
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT)); buttons.add(prepare); buttons.add(run); buttons.add(cancel);
        JPanel north = new JPanel(new BorderLayout(4, 4)); north.add(roster); north.add(buttons, BorderLayout.SOUTH);
        add(north, BorderLayout.NORTH);
        JTable table = new JTable(jobs); table.setAutoCreateRowSorter(false);
        table.getColumnModel().getColumn(6).setPreferredWidth(280);
        views.addTab("Job / data-sharing preview", new JScrollPane(preview));
        views.addTab("Report / local tool trace", new JScrollPane(report));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), views); split.setResizeWeight(.22);
        add(split); add(status, BorderLayout.SOUTH);
        run.setEnabled(false); cancel.setEnabled(false);
        prepare.addActionListener(e -> preparePlan()); run.addActionListener(e -> start()); cancel.addActionListener(e -> cancel());
    }
    private static JTextArea text() { var text = new JTextArea(16, 80); text.setEditable(false); text.setLineWrap(true); text.setWrapStyleWord(true); return text; }

    void preparePlan() {
        if (running != null) return;
        try {
            var snapshot = evidence.get(); List<EvidenceAgentJobs.Binding> bindings = new ArrayList<>();
            List<LlmClient.LlmCredential> available = List.copyOf(credentials.get());
            for (var row : rows) {
                LlmProvider provider = (LlmProvider) row.provider().getSelectedItem();
                var credential = available.stream().filter(c -> c.provider() == provider).findFirst()
                        .orElseThrow(() -> new IllegalArgumentException("Enable " + provider.label() + " in AI analysis and supply its key/environment variable."));
                bindings.add(new EvidenceAgentJobs.Binding(row.job().role(), credential, (Integer) row.output().getValue(), (Integer) row.tools().getValue()));
            }
            prepared = EvidenceAgentJobs.plan(snapshot, bindings); preview.setText(EvidenceAgentJobs.preview(prepared));
            preview.setCaretPosition(0); views.setSelectedIndex(0); resetTable(prepared); run.setEnabled(true);
            status.setText("Review recipients, procedures, tools, evidence and call limits, then click Run previewed jobs.");
        } catch (IllegalArgumentException ex) { invalidatePlan(); status.setText(ex.getMessage()); }
    }
    private void resetTable(EvidenceAgentJobs.Plan plan) {
        jobs.setRowCount(0);
        for (var job : EvidenceAgentJobs.JOBS) {
            var credential = plan.binding(job.role()).credential();
            jobs.addRow(new Object[]{job.id(), job.role().title(), credential.provider().label() + " / " + credential.model(), "QUEUED", 0, 0, "Awaiting explicit run"});
        }
    }
    void start() {
        if (prepared == null || running != null) return;
        var plan = prepared; long token = ++generation; busy(true); report.setText(""); views.setSelectedIndex(1);
        status.setText("Five-agent run " + plan.runId() + ": local evidence analysis and provider calls only.");
        try {
            running = runner.run(plan, event -> {
                if (token != generation) return;
                int index = EvidenceAgentJobs.JOBS.stream().map(EvidenceAgentJobs.Job::id).toList().indexOf(event.jobId());
                jobs.setValueAt(event.state().name(), index, 3); jobs.setValueAt(event.calls(), index, 4);
                jobs.setValueAt(event.tools(), index, 5); jobs.setValueAt(event.detail(), index, 6);
            }, outcome -> {
                if (token != generation) return;
                String rendered = EvidenceAgentRunner.render(plan, outcome);
                report.setText(rendered.length() <= 300_000 ? rendered : rendered.substring(0, 300_000) + "\n[display capped]");
                report.setCaretPosition(0); running = null; busy(false); invalidatePlan();
                status.setText("Run " + outcome.state() + "; " + outcome.calls() + " provider calls. Candidates remain unverified.");
            });
        } catch (RuntimeException ex) { running = null; busy(false); invalidatePlan(); status.setText("Could not start jobs; the extension may be unloading."); }
    }
    void contextChanged() { cancel(); invalidatePlan(); }
    private void invalidatePlan() { prepared = null; run.setEnabled(false); preview.setText("Plan out of date. Preview the jobs after editing evidence, provider settings or budgets."); }
    void cancel() {
        if (running == null) return;
        generation++; running.cancel(true); running = null; busy(false);
        for (int i = 0; i < jobs.getRowCount(); i++) if (!List.of("COMPLETED", "FAILED", "SKIPPED").contains(jobs.getValueAt(i, 3)))
            jobs.setValueAt("CANCELLED", i, 3);
        invalidatePlan(); status.setText("Cancelled; no further jobs/tool calls will start. Provider requests already received cannot be recalled.");
    }
    private void busy(boolean busy) {
        prepare.setEnabled(!busy); run.setEnabled(false); cancel.setEnabled(busy);
        for (var row : rows) { row.provider().setEnabled(!busy); row.output().setEnabled(!busy); row.tools().setEnabled(!busy); }
    }
}
