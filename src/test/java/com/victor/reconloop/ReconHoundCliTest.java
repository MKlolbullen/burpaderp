package com.victor.reconloop;

import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.Rule;

import java.nio.file.Files;
import java.nio.file.Path;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.util.concurrent.atomic.AtomicInteger;
import com.sun.net.httpserver.HttpServer;

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
    @Test public void liveModeFailsClosedWithoutContactsOrOverwritingReportsEvenWhenFailOnNone() throws Exception {
        AtomicInteger contacts = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            contacts.incrementAndGet(); exchange.sendResponseHeaders(200, -1); exchange.close();
        });
        server.start();
        try {
            Path report = temporaryFolder.newFile("existing.sarif").toPath();
            Files.writeString(report, "existing report");
            ByteArrayOutputStream errors = new ByteArrayOutputStream();
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/?secret=hidden";
            assertEquals(3, ReconHoundCli.run(new String[]{url, "--fail-on", "none", "-o", report.toString()}, new PrintStream(errors)));
            assertEquals("existing report", Files.readString(report));
            assertEquals(0, contacts.get());
            assertTrue(errors.toString().contains("#44"));
            assertTrue(!errors.toString().contains("hidden"));
        } finally { server.stop(0); }
    }

    @Test public void offlineBodiesProduceSarifAndSeverityExitsWithoutFetchingMetadataUrl() throws Exception {
        Path body = temporaryFolder.newFile("response.js").toPath();
        Path report = temporaryFolder.getRoot().toPath().resolve("reports/result.sarif");
        Files.writeString(body, "el.innerHTML = location.hash;");
        String[] args = {"--body-file", body.toString(), "--content-type", "application/javascript", "--fail-on", "medium",
                "-o", report.toString(), "https://does-not-resolve.invalid/app.js"};
        assertEquals(1, ReconHoundCli.run(args, new PrintStream(new ByteArrayOutputStream())));
        String sarif = Files.readString(report);
        assertTrue(sarif.contains("domxss-"));
        assertTrue(sarif.contains("does-not-resolve.invalid/app.js"));
        assertTrue(sarif.contains("\"version\":\"2.1.0\""));
        args[5] = "none";
        assertEquals(0, ReconHoundCli.run(args, new PrintStream(new ByteArrayOutputStream())));
    }

    @Test public void offlineGfCredentialCandidatesAreRedactedAndPublicIdentifiersDoNotFailHighThreshold() throws Exception {
        Path body = temporaryFolder.newFile("gf-response.txt").toPath();
        Path report = temporaryFolder.getRoot().toPath().resolve("gf.sarif");
        String secret = "amzn.mws." + "1234abcd-5678-90ab-cdef-1234567890ab";
        Files.writeString(body, secret);
        String[] args = {"--body-file", body.toString(), "--content-type", "text/plain", "--fail-on", "high",
                "-o", report.toString(), "https://does-not-resolve.invalid/"};
        assertEquals(1, ReconHoundCli.run(args, new PrintStream(new ByteArrayOutputStream())));
        String sarif = Files.readString(report);
        assertTrue(sarif.contains("gf-aws-mws-token")); assertTrue(!sarif.contains(secret));
        Files.writeString(body, "api.example.test 192.168.1.1");
        assertEquals(0, ReconHoundCli.run(args, new PrintStream(new ByteArrayOutputStream())));
    }

    @Test public void offlineInputRequiresOneMetadataUrlAndARegularFile() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> ReconHoundCli.parseOptions(new String[]{"--body-file", "body.txt"}));
        assertThrows(IllegalArgumentException.class, () -> ReconHoundCli.parseOptions(new String[]{"--body-file", "body.txt", "https://one.test", "https://two.test"}));
        assertEquals(2, ReconHoundCli.run(new String[]{"--body-file", temporaryFolder.getRoot().toString(), "https://one.test"},
                new PrintStream(new ByteArrayOutputStream())));
    }

}
