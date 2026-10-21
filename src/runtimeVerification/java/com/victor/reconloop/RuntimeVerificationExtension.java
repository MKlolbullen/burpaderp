package com.victor.reconloop;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import javax.swing.*;
import java.awt.BorderLayout;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

/** Separate manual harness entry point. No scanning, auto-sending, scope changes or config changes. */
public final class RuntimeVerificationExtension implements BurpExtension {
    @Override public void initialize(MontoyaApi api) {
        api.extension().setName("Recon Hound runtime verification");
        AtomicReference<RuntimeVerificationCases> active = new AtomicReference<>(); AtomicBoolean closed = new AtomicBoolean();
        ExecutorService worker = Executors.newSingleThreadExecutor(task -> { Thread t = new Thread(task, "Recon-Hound-runtime-verification"); t.setDaemon(true); return t; });
        api.extension().registerUnloadingHandler(() -> { closed.set(true); var running = active.get(); if (running != null) running.cancel(); worker.shutdownNow(); });
        SwingUtilities.invokeLater(() -> {
            if (closed.get()) return;
            JPanel panel = new JPanel(new BorderLayout());
            JTextArea config = new JTextArea("{\n  \"host\": \"fixture.example.test\",\n  \"address\": \"REPLACE_WITH_OWNED_PUBLIC_IP\",\n  \"httpPort\": 18080,\n  \"httpsPort\": 18443,\n  \"directResolver\": \"system\",\n  \"profile\": \"direct-baseline\"\n}", 12, 80);
            panel.add(new JScrollPane(config), BorderLayout.CENTER);
            JPanel controls = new JPanel(); JButton start = new JButton("Run fixture verification (at most 6 API dispatches)");
            JButton cancel = new JButton("Cancel"); JLabel status = new JLabel("Idle. Both fixture origins must already be in Burp scope.");
            controls.add(start); controls.add(cancel); panel.add(controls, BorderLayout.NORTH); panel.add(status, BorderLayout.SOUTH);
            cancel.addActionListener(event -> { var running = active.get(); if (running != null) { running.cancel(); status.setText("Cancellation requested; an in-flight Burp request may still finish."); } });
            start.addActionListener(event -> {
                final RuntimeVerificationCases.Config parsed;
                try { parsed = RuntimeVerificationCases.Config.parse(config.getText()); }
                catch (RuntimeException invalid) { status.setText(invalid.getMessage()); return; }
                JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("burp-runtime-evidence.json"));
                if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
                Path output = chooser.getSelectedFile().toPath().toAbsolutePath();
                if (Files.exists(output)) { status.setText("Choose a new file; existing evidence is never overwritten."); return; }
                RuntimeVerificationCases experiment = new RuntimeVerificationCases(api);
                if (closed.get() || !active.compareAndSet(null, experiment)) return;
                start.setEnabled(false); status.setText("Running synthetic fixture requests. Configure Burp response timeouts before starting.");
                try { worker.execute(() -> {
                    try (FileChannel channel = openEvidence(output)) {
                        var report = experiment.run(parsed, snapshot -> {
                            byte[] bytes = (Json.write(snapshot) + "\n").getBytes(StandardCharsets.UTF_8);
                            try {
                                channel.position(0); ByteBuffer buffer = ByteBuffer.wrap(bytes);
                                while (buffer.hasRemaining()) channel.write(buffer);
                                channel.truncate(bytes.length); channel.force(true);
                            } catch (java.io.IOException e) { experiment.cancel(); throw new java.io.UncheckedIOException(e); }
                        });
                        SwingUtilities.invokeLater(() -> status.setText(report.get("state") + ". API evidence saved; independent fixture/packet review remains required."));
                    } catch (Exception failure) {
                        experiment.cancel(); api.logging().logToError("Runtime verification failed", failure);
                        SwingUtilities.invokeLater(() -> status.setText("Verification incomplete. Inspect the partial evidence file and Burp error log."));
                    } finally { active.compareAndSet(experiment, null); SwingUtilities.invokeLater(() -> start.setEnabled(!closed.get())); }
                }); } catch (RejectedExecutionException unloading) { active.compareAndSet(experiment, null); }
            });
            api.userInterface().registerSuiteTab("Recon runtime verification", panel);
        });
        api.logging().logToOutput("Runtime harness loaded; no requests sent. See docs/BURP_RUNTIME_KIT.md. Results do not attest physical peer enforcement.");
    }

    private static FileChannel openEvidence(Path path) throws java.io.IOException {
        var modes = Set.<OpenOption>of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        return Files.getFileStore(path.getParent()).supportsFileAttributeView("posix")
                ? FileChannel.open(path, modes, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
                : FileChannel.open(path, modes);
    }
}
