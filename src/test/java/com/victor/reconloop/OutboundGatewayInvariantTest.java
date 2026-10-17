package com.victor.reconloop;

import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.assertTrue;

/**
 * Architectural guardrail: target-directed code must dispatch through ActiveRequestGateway instead
 * of calling Montoya HTTP directly. CertificateTransparencyClient is intentionally exempt because
 * it talks only to the public crt.sh OSINT service, not to a target.
 */
public class OutboundGatewayInvariantTest {
    private static final String DIRECT_MONTOYA_SEND = "api.http().sendRequest(";
    private static final Set<String> EXTERNAL_SERVICE_EXEMPTIONS = Set.of(
            "CertificateTransparencyClient.java"
    );

    @Test
    public void targetDirectedSourcesCannotBypassRequestGateway() throws IOException {
        Path sourceRoot = Path.of("src", "main", "java", "com", "victor", "reconloop");
        List<String> violations = new ArrayList<>();

        try (var files = Files.walk(sourceRoot)) {
            files.filter(path -> path.toString().endsWith(".java"))
                    .filter(path -> !EXTERNAL_SERVICE_EXEMPTIONS.contains(path.getFileName().toString()))
                    .forEach(path -> {
                        try {
                            String source = Files.readString(path);
                            if (source.contains(DIRECT_MONTOYA_SEND)) {
                                violations.add(sourceRoot.relativize(path).toString());
                            }
                        } catch (IOException e) {
                            throw new RuntimeException(e);
                        }
                    });
        }

        assertTrue("Direct Montoya target sends bypass ActiveRequestGateway: " + violations,
                violations.isEmpty());
    }
}
