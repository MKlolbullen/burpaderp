package com.victor.reconloop;

import javax.swing.*;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.function.Consumer;
import java.util.function.Supplier;

/** Session-only evidence workspace. Staging/importing is local; only Analyze preview calls a provider. */
final class AiAnalysisPanel extends JPanel {
    @FunctionalInterface interface Runner {
        Future<?> run(List<LlmClient.LlmCredential> credentials, AiAnalysis.Snapshot snapshot,
                      Consumer<AiAnalysis.ProviderReport> onReport, Runnable onDone);
    }
    private final Supplier<List<LlmClient.LlmCredential>> credentials;
    private final Runner runner;
    private final DefaultListModel<AiAnalysis.Source> sources = new DefaultListModel<>();
    private final JList<AiAnalysis.Source> list = new JList<>(sources);
    final JTextArea editor = new JTextArea(8, 60);
    final JTextField focus = new JTextField(60);
    final JTextArea preview = new JTextArea(12, 80);
    final JTextArea results = new JTextArea(14, 80);
    final JButton prepare = new JButton("Preview analysis");
    final JButton send = new JButton("Analyze preview");
    final JButton cancel = new JButton("Cancel");
    private final JButton add = new JButton("Add pasted text");
    private final JButton file = new JButton("Import UTF-8 files…");
    private final JButton remove = new JButton("Remove source");
    private final JLabel status = new JLabel("Stage HTTP exchanges or text files. Nothing has been sent.");
    private final JTabbedPane output = new JTabbedPane();
    private AiAnalysis.Snapshot prepared;
    private List<LlmClient.LlmCredential> recipients = List.of();
    private Future<?> running;
    private int editing = -1, nextId = 1;
    private long generation;
    private boolean loading, importing;

    AiAnalysisPanel(Supplier<List<LlmClient.LlmCredential>> credentials, Runner runner) {
        super(new BorderLayout(4, 4)); this.credentials = credentials; this.runner = runner;
        JPanel tools = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tools.add(add); tools.add(file); tools.add(remove); tools.add(prepare); tools.add(send); tools.add(cancel);
        JPanel top = new JPanel(new BorderLayout());
        top.add(tools, BorderLayout.NORTH);
        JPanel question = new JPanel(new BorderLayout(4, 4));
        question.add(new JLabel("Review focus (optional):"), BorderLayout.WEST); question.add(focus);
        top.add(question, BorderLayout.SOUTH); add(top, BorderLayout.NORTH);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setVisibleRowCount(4);
        JSplitPane sourcePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(list), new JScrollPane(editor));
        sourcePane.setResizeWeight(.25);
        preview.setEditable(false); results.setEditable(false);
        preview.setLineWrap(true); preview.setWrapStyleWord(true);
        results.setLineWrap(true); results.setWrapStyleWord(true);
        output.addTab("Exact outbound preview", new JScrollPane(preview));
        output.addTab("Candidate findings / suggested PoCs", new JScrollPane(results));
        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, sourcePane, output);
        split.setResizeWeight(.35); add(split);
        JPanel bottom = new JPanel(new GridLayout(0, 1));
        bottom.add(status);
        bottom.add(new JLabel("Redaction is best effort: review the preview for sensitive data. PoCs are suggestions and are never executed."));
        add(bottom, BorderLayout.SOUTH);
        send.setEnabled(false); cancel.setEnabled(false);
        DocumentListener changes = new DocumentListener() {
            public void insertUpdate(DocumentEvent e) { invalidatePreview(); }
            public void removeUpdate(DocumentEvent e) { invalidatePreview(); }
            public void changedUpdate(DocumentEvent e) { invalidatePreview(); }
        };
        editor.getDocument().addDocumentListener(changes); focus.getDocument().addDocumentListener(changes);
        list.addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || loading) return;
            try { saveEditor(); load(list.getSelectedIndex()); }
            catch (IllegalArgumentException ex) {
                loading = true; list.setSelectedIndex(editing); loading = false; message(ex.getMessage());
            }
        });
        add.addActionListener(e -> {
            try { stage(AiAnalysis.Kind.TEXT, "Pasted text", ""); }
            catch (IllegalArgumentException ex) { message(ex.getMessage()); }
        });
        file.addActionListener(e -> importFiles());
        remove.addActionListener(e -> {
            int index = list.getSelectedIndex(); if (index < 0) return;
            loading = true; editing = -1; sources.remove(index); list.clearSelection(); loading = false;
            load(-1); invalidatePreview();
        });
        prepare.addActionListener(e -> preparePreview());
        send.addActionListener(e -> startReview());
        cancel.addActionListener(e -> cancelReview());
    }

    void stage(AiAnalysis.Kind kind, String name, String text) {
        cancelReview(); saveEditor();
        AiAnalysis.Source source = new AiAnalysis.Source("s" + nextId, kind, name, text);
        List<AiAnalysis.Source> proposed = sourceList(); proposed.add(source); AiAnalysis.validateSources(proposed);
        nextId++; sources.addElement(source); list.setSelectedIndex(sources.size() - 1);
        invalidatePreview(); status.setText(sources.size() + " staged source(s); nothing sent. Preview before analysis.");
    }

    private List<AiAnalysis.Source> sourceList() {
        List<AiAnalysis.Source> out = new ArrayList<>();
        for (int i = 0; i < sources.size(); i++) out.add(sources.get(i));
        return out;
    }
    private void saveEditor() {
        if (editing < 0 || editing >= sources.size()) return;
        var old = sources.get(editing);
        var updated = new AiAnalysis.Source(old.id(), old.kind(), old.name(), editor.getText());
        loading = true;
        try { sources.set(editing, updated); } finally { loading = false; }
    }
    private void load(int index) {
        loading = true;
        try { editing = index; editor.setText(index < 0 ? "" : sources.get(index).text()); editor.setCaretPosition(0); }
        finally { loading = false; }
    }
    void invalidatePreview() {
        if (loading) return;
        prepared = null; recipients = List.of(); send.setEnabled(false);
        preview.setText("Preview out of date. Click Preview analysis after finishing your edits.");
    }
    void credentialsChanged() { cancelReview(); invalidatePreview(); }

    void preparePreview() {
        try {
            saveEditor();
            List<LlmClient.LlmCredential> selected = List.copyOf(credentials.get());
            if (selected.isEmpty()) throw new IllegalArgumentException("Enable a provider with a key above (or its environment variable).");
            AiAnalysis.Snapshot snapshot = AiAnalysis.prepare(sourceList(), focus.getText());
            recipients = selected; prepared = snapshot;
            StringBuilder text = new StringBuilder("Recipients/models (one call each, no automatic retries):\n");
            for (var c : selected) text.append(c.provider().label()).append(" / ").append(c.model()).append('\n');
            text.append("\nRedactions: ").append(snapshot.redactions()).append(". Context characters: ").append(snapshot.prompt().length())
                    .append(". Output limit: 4096 tokens per provider.\n\nSYSTEM MESSAGE:\n").append(AiAnalysis.SYSTEM)
                    .append("\nUSER MESSAGE (exact JSON content):\n").append(snapshot.prompt());
            preview.setText(text.toString()); preview.setCaretPosition(0); output.setSelectedIndex(0);
            send.setEnabled(true); status.setText("Review the outbound content and recipients, then click Analyze preview to send.");
        } catch (IllegalArgumentException ex) { invalidatePreview(); message(ex.getMessage()); }
    }

    void startReview() {
        if (prepared == null || recipients.isEmpty() || running != null) return;
        AiAnalysis.Snapshot snapshot = prepared; List<LlmClient.LlmCredential> selected = recipients;
        long token = ++generation; setBusy(true); results.setText(""); output.setSelectedIndex(1);
        status.setText("Reviewing with " + selected.size() + " provider(s). No target requests are sent.");
        try {
            running = runner.run(selected, snapshot, report -> {
                if (token != generation) return;
                String next = "\n=== " + report.provider().label() + " / " + report.model() + " ===\n"
                        + AiAnalysis.render(report.report(), snapshot);
                int remaining = 300_000 - results.getDocument().getLength();
                if (remaining > 0) results.append(next.length() <= remaining ? next : next.substring(0, remaining) + "\n[display capped]");
            }, () -> {
                if (token != generation) return;
                running = null; setBusy(false); invalidatePreview(); status.setText("Review complete. Findings are unverified; suggested PoCs have not been run.");
            });
        } catch (RuntimeException ex) {
            running = null; setBusy(false); invalidatePreview(); message("Could not start review; the extension may be unloading.");
        }
    }

    void cancelReview() {
        if (running == null) return;
        generation++; running.cancel(true); running = null; setBusy(false); invalidatePreview();
        status.setText("Cancelled. Requests already received by a provider cannot be recalled; no further provider calls will start.");
    }
    private void setBusy(boolean busy) {
        send.setEnabled(false); cancel.setEnabled(busy); prepare.setEnabled(!busy && !importing);
        add.setEnabled(!busy && !importing); file.setEnabled(!busy && !importing); remove.setEnabled(!busy && !importing);
        editor.setEditable(!busy && !importing); focus.setEditable(!busy && !importing); list.setEnabled(!busy && !importing);
    }
    private void message(String text) { status.setText(text); }
    void showMessage(String text) { message(text); }

    private void importFiles() {
        JFileChooser chooser = new JFileChooser(); chooser.setMultiSelectionEnabled(true);
        chooser.setDialogTitle("Import UTF-8 JavaScript, source maps, API specs or other text (no upload)");
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;
        File[] selected = chooser.getSelectedFiles();
        if (selected.length + sources.size() > AiAnalysis.MAX_SOURCES) { message("At most 12 sources per review."); return; }
        invalidatePreview(); importing = true; setBusy(false);
        new SwingWorker<List<AiAnalysis.Source>, Void>() {
            protected List<AiAnalysis.Source> doInBackground() throws Exception {
                List<AiAnalysis.Source> read = new ArrayList<>();
                for (File f : selected) read.add(AiAnalysis.readFile("s1", f.toPath()));
                return read;
            }
            protected void done() {
                try { for (var source : get()) stage(source.kind(), source.name(), source.text()); }
                catch (Exception ex) { message("Import stopped: use UTF-8 text, ≤256 KiB and ≤48,000 characters per file; ≤144,000 characters total."); }
                finally { importing = false; setBusy(false); }
            }
        }.execute();
    }
}
