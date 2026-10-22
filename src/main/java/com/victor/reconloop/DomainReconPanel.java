package com.victor.reconloop;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

/** Domain form, exportable dependency plan and the bounded first executable stage. */
final class DomainReconPanel extends JPanel {
    @FunctionalInterface interface Runner {
        Future<?> run(DomainReconProcess.Plan plan, Consumer<DomainReconProcess.Event> events, Consumer<DomainReconProcess.Outcome> done);
    }
    final JTextField target = new JTextField(30), executable = new JTextField("reconctl", 30), output = new JTextField(30);
    final JSpinner hosts = new JSpinner(new SpinnerNumberModel(5000, 1, 25000, 500));
    final JSpinner seconds = new JSpinner(new SpinnerNumberModel(300, 5, 1200, 30));
    final JButton prepare = new JButton("Preview recon chain"), start = new JButton("Run passive enumeration"), cancel = new JButton("Cancel job");
    final JButton savePlan = new JButton("Export chain JSON…"), importHosts = new JButton("Import hosts into Burp…");
    final JTextArea preview = text(14), progress = text(8);
    final DefaultTableModel chain = model("Stage", "Depends on", "Tool", "Execution support", "Output", "Detail");
    final DefaultTableModel results = model("Hostname", "First source");
    final JLabel status = new JLabel("Enter an authorised domain and output directory; preview before running.");
    private final Runner runner;
    private final BiConsumer<Path, Consumer<String>> importer;
    private final JButton chooseExecutable = new JButton("Browse…"), chooseOutput = new JButton("Browse…");
    private final JTabbedPane views = new JTabbedPane();
    private DomainReconProcess.Plan prepared, completed;
    private String chainJson;
    private Future<?> running;
    private long generation;

    DomainReconPanel(Runner runner, BiConsumer<Path, Consumer<String>> importer) {
        super(new BorderLayout(4, 4)); this.runner = runner; this.importer = importer;
        JPanel form = new JPanel(new GridBagLayout());
        addField(form, 0, "Target domain", target, new JLabel("Bare domain; no URL or wildcard"));
        addField(form, 1, "Trusted reconctl executable", executable, chooseExecutable);
        addField(form, 2, "Output directory", output, chooseOutput);
        JPanel limits = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        limits.add(new JLabel("Max unique hosts")); limits.add(hosts); limits.add(new JLabel("Seconds per tool")); limits.add(seconds);
        addField(form, 3, "Run limits", limits, new JLabel("assetfinder → subfinder → chaos"));
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        for (JButton button : List.of(prepare, savePlan, start, cancel, importHosts)) buttons.add(button);
        JPanel north = new JPanel(new BorderLayout(4, 4)); north.add(form); north.add(buttons, BorderLayout.SOUTH); add(north, BorderLayout.NORTH);
        JTable chainTable = new JTable(chain); chainTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {100, 170, 200, 200, 220, 650};
        for (int i = 0; i < widths.length; i++) chainTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        views.addTab("Chained plan / support", new JScrollPane(chainTable));
        views.addTab("Preview / argument vector", new JScrollPane(preview));
        JTable hostTable = new JTable(results); hostTable.setAutoCreateRowSorter(true);
        views.addTab("Collected hosts", new JScrollPane(hostTable));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, views, new JScrollPane(progress)); split.setResizeWeight(.8); add(split);
        add(status, BorderLayout.SOUTH);
        start.setEnabled(false); cancel.setEnabled(false); savePlan.setEnabled(false); importHosts.setEnabled(false);
        prepare.addActionListener(e -> preparePlan()); start.addActionListener(e -> start()); cancel.addActionListener(e -> cancel());
        savePlan.addActionListener(e -> exportPlan()); importHosts.addActionListener(e -> importHosts());
        chooseExecutable.addActionListener(e -> choose(executable, false)); chooseOutput.addActionListener(e -> choose(output, true));
        DocumentListener changed = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { invalidatePlan(); }
            public void removeUpdate(DocumentEvent e) { invalidatePlan(); }
            public void changedUpdate(DocumentEvent e) { invalidatePlan(); }
        };
        for (JTextField field : List.of(target, executable, output)) field.getDocument().addDocumentListener(changed);
        hosts.addChangeListener(e -> invalidatePlan()); seconds.addChangeListener(e -> invalidatePlan());
    }
    private static DefaultTableModel model(String... columns) {
        return new DefaultTableModel(columns, 0) { @Override public boolean isCellEditable(int row, int column) { return false; } };
    }
    private static JTextArea text(int rows) {
        JTextArea area = new JTextArea(rows, 80); area.setEditable(false); area.setLineWrap(true); area.setWrapStyleWord(true); return area;
    }
    private static void addField(JPanel panel, int row, String label, Component field, Component action) {
        GridBagConstraints c = new GridBagConstraints(); c.gridy = row; c.insets = new Insets(2, 4, 2, 4); c.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel(label), c); c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL; panel.add(field, c);
        c.gridx = 2; c.weightx = 0; panel.add(action, c);
    }
    void preparePlan() {
        if (running != null) return;
        try {
            if (output.getText().isBlank()) throw new IllegalArgumentException("Choose an output directory.");
            var plan = new DomainReconProcess.Plan(target.getText(), executable.getText(), Path.of(output.getText()),
                    UUID.randomUUID().toString(), (Integer) hosts.getValue(), (Integer) seconds.getValue());
            var manifest = ReconChainPlan.create(plan.domain());
            manifest.put("enumeration_run", java.util.Map.of("run_id", plan.runId(), "output_directory", plan.runDir().toString(),
                    "max_hosts", plan.maxHosts(), "tool_timeout_seconds", plan.toolSeconds(), "command", plan.command()));
            chainJson = Json.write(manifest); chain.setRowCount(0);
            for (var row : ReconChainPlan.rows(manifest)) chain.addRow(new Object[]{row.stage(), row.dependencies(), row.tool(), row.mode(), row.output(), row.detail()});
            prepared = plan; completed = null; importHosts.setEnabled(false);
            preview.setText(plan.preview() + "\n\nFull dependency manifest:\n" + chainJson); preview.setCaretPosition(0);
            views.setSelectedIndex(0); start.setEnabled(true); savePlan.setEnabled(true);
            status.setText("Chain is a plan. Run executes only assetfinder, subfinder and chaos; httpx/crawlers remain blocked (#44).");
        } catch (IllegalArgumentException | IllegalStateException e) { invalidatePlan(); status.setText(e.getMessage()); }
    }
    void start() {
        if (prepared == null || running != null) return;
        DomainReconProcess.Plan plan = prepared; long token = ++generation;
        busy(true); results.setRowCount(0); progress.setText("Run " + plan.runId() + "\nOutput: " + plan.runDir() + "\n");
        views.setSelectedIndex(2); status.setText("Passive provider queries running. Hosts appear after each tool completes.");
        try {
            running = runner.run(plan, event -> {
                if (token != generation) return;
                if (event.type().equals("host")) results.addRow(new Object[]{event.host(), event.tool()});
                else if (event.type().equals("tool")) progress.append(event.tool() + ": " + event.state() + " · " + event.count() + " unique hosts · " + event.detail() + "\n");
            }, outcome -> {
                if (token != generation) return;
                running = null; completed = plan; busy(false); prepared = null; start.setEnabled(false);
                boolean usable = List.of("SUCCESS", "PARTIAL").contains(outcome.state());
                importHosts.setEnabled(usable && outcome.count() > 0 && Files.isRegularFile(plan.runDir().resolve("hosts.jsonl")));
                progress.append(outcome.state() + ": " + outcome.count() + " hosts. " + outcome.detail() + "\n");
                status.setText("Run " + outcome.state() + "; " + outcome.count() + " hosts. HTTPX was not executed. Preview again to start a new run.");
            });
        } catch (RuntimeException e) { running = null; busy(false); invalidatePlan(); status.setText("Could not schedule domain recon job."); }
    }
    void cancel() {
        if (running == null) return;
        Future<?> job = running; running = null; generation++; job.cancel(true);
        busy(false); invalidatePlan();
        progress.append("Cancellation requested; partial files may be available.\n");
        status.setText("Cancellation requested. The worker stops the job and observed children; preview again for a new run.");
    }
    private void importHosts() {
        if (completed == null || !importHosts.isEnabled()) return;
        long token = generation; importHosts.setEnabled(false);
        importer.accept(completed.runDir().resolve("hosts.jsonl"), message -> { if (token == generation) { status.setText(message); } });
    }
    private void exportPlan() {
        if (chainJson == null) return;
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("recon-chain.json"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        Path path = chooser.getSelectedFile().toPath();
        if (Files.exists(path) && JOptionPane.showConfirmDialog(this, "Replace the existing plan file?", "Export plan", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        try { Files.writeString(path, chainJson + "\n", StandardCharsets.UTF_8); status.setText("Saved chain plan: " + path); }
        catch (java.io.IOException e) { status.setText("Could not write chain plan."); }
    }
    private void choose(JTextField field, boolean directory) {
        JFileChooser chooser = new JFileChooser(); if (directory) chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) field.setText(chooser.getSelectedFile().getAbsolutePath());
    }
    private void invalidatePlan() {
        prepared = null; completed = null; chainJson = null; start.setEnabled(false); savePlan.setEnabled(false); importHosts.setEnabled(false);
        if (running == null) { generation++; preview.setText(""); chain.setRowCount(0); }
    }
    private void busy(boolean value) {
        for (Component component : List.of(target, executable, output, hosts, seconds, chooseExecutable, chooseOutput, prepare, savePlan)) component.setEnabled(!value);
        start.setEnabled(false); cancel.setEnabled(value); importHosts.setEnabled(false);
    }
}
