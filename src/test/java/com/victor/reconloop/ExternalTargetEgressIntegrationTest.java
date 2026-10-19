package com.victor.reconloop;

import org.junit.Test;
import org.junit.Rule;
import org.junit.rules.TemporaryFolder;
import javax.swing.SwingUtilities;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.ArrayList;
import static org.junit.Assert.*;

public class ExternalTargetEgressIntegrationTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();

    @Test public void sqlmapNeverStartsEvenForVersionChecksOrDestructiveExtraArgs() throws Exception {
        Path marker = temp.getRoot().toPath().resolve("started");
        Path binary = temp.newFile("sqlmap").toPath();
        Files.writeString(binary, "#!/bin/sh\ntouch '" + marker + "'\n");
        assertTrue(binary.toFile().setExecutable(true));
        SqlmapClient client = new SqlmapClient(binary.toString());
        assertFalse(client.isAvailable());
        for (String method : List.of("GET", "POST", "DELETE")) {
            var result = client.run(new SqlmapClient.Target("https://example.test", method, "q", "secret", "auth"),
                    5, 3, "BEUSTQ", "--dump --proxy=http://127.0.0.1:8080 --os-shell", 120);
            assertFalse(result.started());
            assertFalse(result.vulnerable());
            assertTrue(result.error().contains("#44"));
            assertTrue(result.rawOutput().isEmpty());
        }
        assertFalse("No process, including --version, may start", Files.exists(marker));
    }

    @Test public void controllerBlocksWithoutQueueingOrDependingOnNativeRiskGrants() throws Exception {
        try (FakeMontoya fake = new FakeMontoya()) {
            ManualExecutor executor = new ManualExecutor();
            ReconController controller = ReconControllerRunLifecycleTest.controller(fake, executor);
            List<String> progress = new ArrayList<>();
            try {
                for (boolean enabled : List.of(false, true)) {
                    controller.setActiveTestsEnabled(enabled);
                    controller.setMutatingActiveRequests(enabled);
                    controller.runSqlmap("https://example.test", "POST", "q", "secret", "auth", 5, 3, "B", "--dump", 10);
                    controller.runPdcpScan("sensitive-key", "team", List.of("https://example.test"), List.of("all"), true, progress::add);
                }
                executor.runAll();
                SwingUtilities.invokeAndWait(() -> {});
                assertEquals(2, progress.size());
                assertTrue(progress.stream().allMatch(s -> s.startsWith("[error]") && s.contains("#44")));
                assertFalse(progress.toString().contains("sensitive-key"));
                assertTrue(fake.sent.isEmpty());
            } finally { controller.shutdown(); }
        }
    }
}
