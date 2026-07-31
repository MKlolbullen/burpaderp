package com.victor.reconloop;

import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.*;

public class SqlmapClientTimeoutTest {

    @Test
    public void terminatesHungProcessAtConfiguredTimeout() throws Exception {
        Path fakeSqlmap = Files.createTempFile("fake-sqlmap", ".sh");
        Files.writeString(fakeSqlmap, "#!/bin/sh\necho started\nsleep 5\necho finished\n");
        assertTrue(fakeSqlmap.toFile().setExecutable(true));

        SqlmapClient client = new SqlmapClient(fakeSqlmap.toString());
        SqlmapClient.Target target = new SqlmapClient.Target(
                "https://app.example.test/search?q=1", "GET", "q", null, null);

        long started = System.nanoTime();
        SqlmapClient.RunResult result = client.run(target, 1, 1, "B", null, 1);
        long elapsedMillis = (System.nanoTime() - started) / 1_000_000L;

        assertTrue(result.started());
        assertFalse(result.vulnerable());
        assertNotNull(result.error());
        assertTrue(result.error().contains("timed out"));
        assertTrue("timeout should stop the five-second process promptly", elapsedMillis < 4_000L);

        Files.deleteIfExists(fakeSqlmap);
    }
}
