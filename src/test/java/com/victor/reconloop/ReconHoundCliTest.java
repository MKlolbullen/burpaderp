package com.victor.reconloop;

import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.Rule;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

public class ReconHoundCliTest {
    @Rule public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Test
    public void parsesOptionsAndDeduplicatesTargetsInInputOrder() throws Exception {
        ReconHoundCli.Options options = ReconHoundCli.parseOptions(new String[]{
                "--fail-on", "MEDIUM", "-o", "reports/result.sarif",
                "https://example.test/a", "https://example.test/a", "http://api.example.test"
        });

        assertEquals("medium", options.failOn());
        assertEquals(Path.of("reports/result.sarif"), options.output());
        assertEquals(2, options.urls().size());
        assertEquals("https://example.test/a", options.urls().get(0));
        assertEquals("http://api.example.test", options.urls().get(1));
    }

    @Test
    public void targetFileSupportsBlankLinesAndComments() throws Exception {
        Path targets = temporaryFolder.newFile("targets.txt").toPath();
        Files.writeString(targets, "# production targets\n\nhttps://one.example/path\n  http://two.example  \n");

        ReconHoundCli.Options options = ReconHoundCli.parseOptions(new String[]{"--file", targets.toString()});

        assertEquals(2, options.urls().size());
        assertEquals("https://one.example/path", options.urls().get(0));
        assertEquals("http://two.example", options.urls().get(1));
    }

    @Test
    public void rejectsMissingValuesUnknownOptionsAndInvalidThresholds() {
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ReconHoundCli.parseOptions(new String[]{"--output"})).getMessage().contains("missing value"));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ReconHoundCli.parseOptions(new String[]{"--wat"})).getMessage().contains("unknown option"));
        assertTrue(assertThrows(IllegalArgumentException.class,
                () -> ReconHoundCli.parseOptions(new String[]{"--fail-on", "urgent"})).getMessage().contains("invalid --fail-on"));
    }

    @Test
    public void rejectsNonHttpAndRelativeTargets() {
        assertThrows(IllegalArgumentException.class,
                () -> ReconHoundCli.parseOptions(new String[]{"file:///etc/passwd"}));
        assertThrows(IllegalArgumentException.class,
                () -> ReconHoundCli.parseOptions(new String[]{"example.test/path"}));
    }

    @Test
    public void recognizesHelpWithoutTargets() throws Exception {
        ReconHoundCli.Options options = ReconHoundCli.parseOptions(new String[]{"--help"});
        assertTrue(options.help());
        assertTrue(options.urls().isEmpty());
    }
}
