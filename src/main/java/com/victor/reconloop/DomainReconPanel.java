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
    final JSpinner maxUrls = new JSpinner(new SpinnerNumberModel(10000,1,25000,1000));
    final JSpinner httpBudget = new JSpinner(new SpinnerNumberModel(100,1,10000,25)), depth=new JSpinner(new SpinnerNumberModel(2,0,5,1));
    final JSpinner perHost=new JSpinner(new SpinnerNumberModel(50,1,10000,10));
    final JCheckBox workflow=new JCheckBox("Include Amass, DNS and archive collectors",true), live=new JCheckBox("Run governed HTTP / crawl / JS phase",false);
    final JButton prepare = new JButton("Preview recon chain"), start = new JButton("Run previewed chain"), cancel = new JButton("Cancel job");
    final JButton savePlan = new JButton("Export chain JSON…"), importHosts = new JButton("Import scoped results into Burp…");
    final JButton review = new JButton("Stage captured evidence for AI review");
    final JTextArea preview = text(14), progress = text(8);
    final DefaultTableModel chain = model("Stage", "Depends on", "Tool", "Execution support", "Output", "Detail");
    final DefaultTableModel results = model("Hostname", "First source");
    final DefaultTableModel urlResults=model("URL candidate","Source"),dnsResults=model("Hostname","DNS metadata"),httpResults=model("URL","Decision / response");
    final JLabel status = new JLabel("Enter an authorised domain and output directory; preview before running.");
    private final Runner runner;
    private final BiConsumer<Path, Consumer<String>> importer;
    private final Consumer<List<AiAnalysis.Source>> reviewer;
    private final JButton chooseExecutable = new JButton("Browse…"), chooseOutput = new JButton("Browse…");
    private final JTabbedPane views = new JTabbedPane();
    private DomainReconProcess.Plan prepared, completed;
    private String chainJson;
    private Future<?> running;
    private long generation;

    DomainReconPanel(Runner runner, BiConsumer<Path, Consumer<String>> importer) {
        this(runner,importer,sources->{});
    }
    DomainReconPanel(Runner runner, BiConsumer<Path, Consumer<String>> importer,Consumer<List<AiAnalysis.Source>> reviewer) {
        super(new BorderLayout(4, 4)); this.runner = runner; this.importer = importer;this.reviewer=reviewer;
        JPanel form = new JPanel(new GridBagLayout());
        addField(form, 0, "Target domain", target, new JLabel("Bare domain; no URL or wildcard"));
        addField(form, 1, "Trusted reconctl executable", executable, chooseExecutable);
        addField(form, 2, "Output directory", output, chooseOutput);
        JPanel limits = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
        limits.add(new JLabel("Max unique hosts")); limits.add(hosts); limits.add(new JLabel("Seconds per tool")); limits.add(seconds);
        limits.add(new JLabel("Max URLs"));limits.add(maxUrls);
        addField(form, 3, "Run limits", limits, new JLabel("Unique per-run artifacts"));
        JPanel httpLimits=new JPanel(new FlowLayout(FlowLayout.LEFT,4,0));httpLimits.add(new JLabel("Total GETs"));httpLimits.add(httpBudget);httpLimits.add(new JLabel("Per host"));httpLimits.add(perHost);httpLimits.add(new JLabel("Depth"));httpLimits.add(depth);
        addField(form,4,"Stages",workflow,new JLabel("Uncheck for the original three-enumerator job"));
        addField(form,5,"Native HTTP",live,new JLabel("Current Burp scope required on every hop"));
        addField(form,6,"HTTP quotas",httpLimits,new JLabel("One ledger; maximum 10 dispatches/sec"));
        JPanel buttons = new JPanel(new GridLayout(0,3,4,4));
        for (JButton button : List.of(prepare, savePlan, start, cancel, importHosts,review)) buttons.add(button);
        JPanel north = new JPanel(new BorderLayout(4, 4)); north.add(form); north.add(buttons, BorderLayout.SOUTH); add(north, BorderLayout.NORTH);
        JTable chainTable = new JTable(chain); chainTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        int[] widths = {100, 170, 200, 200, 220, 650};
        for (int i = 0; i < widths.length; i++) chainTable.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        views.addTab("Chained plan / support", new JScrollPane(chainTable));
        views.addTab("Preview / argument vector", new JScrollPane(preview));
        JTable hostTable = new JTable(results); hostTable.setAutoCreateRowSorter(true);
        JTabbedPane collected=new JTabbedPane();collected.addTab("Hosts",new JScrollPane(hostTable));
        collected.addTab("DNS",new JScrollPane(new JTable(dnsResults)));collected.addTab("Archive URLs",new JScrollPane(new JTable(urlResults)));collected.addTab("Native HTTP",new JScrollPane(new JTable(httpResults)));
        views.addTab("Collected results", collected);
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, views, new JScrollPane(progress)); split.setResizeWeight(.8); add(split);
        add(status, BorderLayout.SOUTH);
        start.setEnabled(false); cancel.setEnabled(false); savePlan.setEnabled(false); importHosts.setEnabled(false);
        review.setEnabled(false);httpBudget.setEnabled(false);depth.setEnabled(false);perHost.setEnabled(false);
        prepare.addActionListener(e -> preparePlan()); start.addActionListener(e -> start()); cancel.addActionListener(e -> cancel());
        savePlan.addActionListener(e -> exportPlan()); importHosts.addActionListener(e -> importHosts());
        review.addActionListener(e->stageReview());
        chooseExecutable.addActionListener(e -> choose(executable, false)); chooseOutput.addActionListener(e -> choose(output, true));
        DocumentListener changed = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { invalidatePlan(); }
            public void removeUpdate(DocumentEvent e) { invalidatePlan(); }
            public void changedUpdate(DocumentEvent e) { invalidatePlan(); }
        };
        for (JTextField field : List.of(target, executable, output)) field.getDocument().addDocumentListener(changed);
        hosts.addChangeListener(e -> invalidatePlan()); seconds.addChangeListener(e -> invalidatePlan());
        maxUrls.addChangeListener(e->invalidatePlan());httpBudget.addChangeListener(e->invalidatePlan());depth.addChangeListener(e->invalidatePlan());perHost.addChangeListener(e->invalidatePlan());
        workflow.addActionListener(e->{if(!workflow.isSelected())live.setSelected(false);live.setEnabled(workflow.isSelected());httpBudget.setEnabled(live.isSelected());depth.setEnabled(live.isSelected());perHost.setEnabled(live.isSelected());invalidatePlan();});
        live.addActionListener(e->{httpBudget.setEnabled(live.isSelected());depth.setEnabled(live.isSelected());perHost.setEnabled(live.isSelected());invalidatePlan();});
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
                    UUID.randomUUID().toString(), (Integer) hosts.getValue(), (Integer) seconds.getValue(),workflow.isSelected(),(Integer)maxUrls.getValue(),live.isSelected()?(Integer)httpBudget.getValue():0,(Integer)depth.getValue(),(Integer)perHost.getValue());
            var manifest = ReconChainPlan.create(plan.domain());
            manifest.put("enumeration_run", java.util.Map.of("run_id", plan.runId(), "output_directory", plan.runDir().toString(),
                    "max_hosts", plan.maxHosts(), "tool_timeout_seconds", plan.toolSeconds(), "command", plan.command()));
            manifest.put("native_http",java.util.Map.of("enabled",plan.httpBudget()>0,"total_get_budget",plan.httpBudget(),"per_host",Math.min(plan.perHost(),plan.httpBudget()),"per_endpoint",Math.min(3,plan.httpBudget()),"depth",plan.depth(),"overall_seconds",plan.toolSeconds(),"response_timeout_ms",15000,"maximum_dispatches_per_second",10,"transport","shared Burp outbound gateway"));
            chainJson = Json.write(manifest); chain.setRowCount(0);
            for (var row : ReconChainPlan.rows(manifest)) chain.addRow(new Object[]{row.stage(), row.dependencies(), row.tool(), row.mode(), row.output(), row.detail()});
            prepared = plan; completed = null; importHosts.setEnabled(false);
            preview.setText(plan.preview() + "\n\nFull dependency manifest:\n" + chainJson); preview.setCaretPosition(0);
            views.setSelectedIndex(0); start.setEnabled(true); savePlan.setEnabled(true);
            status.setText(plan.workflow()?"Runnable provider / DNS / archive chain"+(plan.httpBudget()>0?" plus bounded native GET crawl.":"; native HTTP disabled."):"Three passive enumerators only. No target probing.");
        } catch (IllegalArgumentException | IllegalStateException e) { invalidatePlan(); status.setText(e.getMessage()); }
    }
    void start() {
        if (prepared == null || running != null) return;
        DomainReconProcess.Plan plan = prepared; long token = ++generation;
        busy(true); results.setRowCount(0);urlResults.setRowCount(0);dnsResults.setRowCount(0);httpResults.setRowCount(0); progress.setText("Run " + plan.runId() + "\nOutput: " + plan.runDir() + "\n");
        views.setSelectedIndex(2); status.setText("Recon chain running. Results appear after each sidecar tool; native observations follow if enabled.");
        try {
            running = runner.run(plan, event -> {
                if (token != generation) return;
                if (event.type().equals("host")) results.addRow(new Object[]{event.host(), event.tool()});
                else if(event.type().equals("url"))urlResults.addRow(new Object[]{event.host(),event.detail().isBlank()?event.tool():event.detail()});
                else if(event.type().equals("dns"))dnsResults.addRow(new Object[]{event.host(),event.detail()});
                else if(event.type().equals("http"))httpResults.addRow(new Object[]{event.host(),event.state()+" · "+event.detail()});
                else if (event.type().equals("tool")) progress.append(event.tool() + ": " + event.state() + " · " + event.count() + " unique hosts · " + event.detail() + "\n");
            }, outcome -> {
                if (token != generation) return;
                running = null; completed = plan; busy(false); prepared = null; start.setEnabled(false);
                boolean usable = List.of("SUCCESS", "PARTIAL").contains(outcome.state());
                importHosts.setEnabled(usable && outcome.count() > 0 && Files.isRegularFile(plan.runDir().resolve("hosts.jsonl")));
                review.setEnabled(Files.isRegularFile(plan.runDir().resolve("native/review-sources.json")));
                progress.append(outcome.state() + ": " + outcome.count() + " hosts. " + outcome.detail() + "\n");
                status.setText("Run " + outcome.state() + "; " + outcome.count() + " hosts. External target tools were not executed; native HTTP results have their own summary.");
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
        importer.accept(completed.runDir().resolve(completed.workflow()?"records.jsonl":"hosts.jsonl"), message -> { if (token == generation) { status.setText(message); } });
    }
    private void stageReview(){
        if(completed==null||!review.isEnabled())return;
        var plan=completed;long token=generation;review.setEnabled(false);
        new SwingWorker<List<AiAnalysis.Source>,Void>(){
            protected List<AiAnalysis.Source> doInBackground()throws Exception{return ReconWorkflowInputs.review(plan);}
            protected void done(){if(token!=generation)return;try{var sources=get();reviewer.accept(sources);status.setText("Staged "+sources.size()+" captured sources locally; preview redaction/provider sharing before analysis.");}catch(Exception e){status.setText("Could not validate captured review sources.");}}
        }.execute();
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
        prepared = null; completed = null; chainJson = null; start.setEnabled(false); savePlan.setEnabled(false); importHosts.setEnabled(false);review.setEnabled(false);
        if (running == null) { generation++; preview.setText(""); chain.setRowCount(0); }
    }
    private void busy(boolean value) {
        for (Component component : List.of(target, executable, output, hosts, seconds,maxUrls,httpBudget,depth,perHost,workflow,live, chooseExecutable, chooseOutput, prepare, savePlan)) component.setEnabled(!value);
        live.setEnabled(!value&&workflow.isSelected());httpBudget.setEnabled(!value&&live.isSelected());depth.setEnabled(!value&&live.isSelected());perHost.setEnabled(!value&&live.isSelected());
        start.setEnabled(false); cancel.setEnabled(value); importHosts.setEnabled(false);review.setEnabled(false);
    }
}
