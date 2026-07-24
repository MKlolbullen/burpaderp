package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class RegexHoundTest {

    private final RegexHound hound = new RegexHound();

    @Test
    public void detectsGitHubClassicPat() {
        // Built by concatenation (rather than one literal) so the fake fixture never appears as a
        // single contiguous token-shaped string in the source, which trips secret-scanning tools.
        String token = "ghp_" + "1234567890" + "abcdefghij";
        String text = "Authorization header leaked: " + token + " in the response";
        List<RegexHound.Finding> findings = hound.scan(text, "response", "https://example.com", false);

        RegexHound.Finding found = findings.stream()
                .filter(f -> f.rule().id().equals("github-classic-pat")).findFirst().orElse(null);
        assertNotNull("expected a github-classic-pat finding", found);
        assertEquals(token, found.value());
        assertEquals(token, text.substring(found.start(), found.end()));
        assertEquals(RegexHound.Severity.CRITICAL, found.rule().severity());
    }

    @Test
    public void detectsSlackWebhookUrl() {
        // Concatenated so this fake fixture never appears as one contiguous webhook-shaped string.
        String url = "https://hooks.slack.com/services/" + "T00000000/B00000000/" + "XXXXXXXXXXXXXXXXXXXXXXXX";
        List<RegexHound.Finding> findings = hound.scan("webhook: " + url, "response", "u", false);

        assertTrue(findings.stream().anyMatch(f -> f.rule().id().equals("slack-webhook") && f.value().equals(url)));
    }

    @Test
    public void detectsGenericJwtShape() {
        // Concatenated (rather than one literal) so this fake fixture never appears as a single
        // contiguous JWT-shaped string in the source, which trips secret-scanning tools.
        String jwt = "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "dGhpc2lzYXNpZ25hdHVyZQ";
        List<RegexHound.Finding> findings = hound.scan("token=" + jwt, "response", "u", false);

        assertTrue(findings.stream().anyMatch(f -> f.rule().id().equals("jwt") && f.value().equals(jwt)));
    }

    @Test
    public void lowEntropyValueIsSuppressed() {
        // "generic-password-assignment" requires minEntropy 2.3; a run of one repeated
        // character has zero Shannon entropy and must never be flagged as a leaked secret.
        List<RegexHound.Finding> findings = hound.scan("password = \"aaaaaaaaaaaaaaaa\"", "response", "u", false);

        assertFalse(findings.stream().anyMatch(f -> f.rule().id().equals("generic-password-assignment")));
    }

    @Test
    public void placeholderValueIsSuppressed() {
        // Long and high-entropy-ish enough to otherwise satisfy generic-secret-assignment's
        // length (>=12) and entropy (>=2.8) gates, so this only passes if the placeholder
        // substring check ("changeme") is what suppresses it.
        List<RegexHound.Finding> findings = hound.scan("api_key = \"changeme12345\"", "response", "u", false);

        assertTrue(findings.isEmpty());
    }

    @Test
    public void infoSeverityOnlyReturnedWhenRequested() {
        String text = "server ip 10.1.2.3 responded";
        assertTrue(hound.scan(text, "response", "u", false).isEmpty());

        List<RegexHound.Finding> withInfo = hound.scan(text, "response", "u", true);
        assertTrue(withInfo.stream().anyMatch(f -> f.rule().id().equals("ipv4") && f.value().equals("10.1.2.3")));
    }

    @Test
    public void invalidIpv4OctetsAreRejected() {
        List<RegexHound.Finding> findings = hound.scan("bogus 999.999.999.999 address", "response", "u", true);

        assertFalse(findings.stream().anyMatch(f -> f.rule().id().equals("ipv4")));
    }

    @Test
    public void redactMasksMiddleOfLongValues() {
        // redact() is a generic masker with no notion of token "shape"; build the fixture with
        // .repeat() so the expected output is unambiguous and it doesn't resemble any real
        // provider's credential format.
        String value = "A".repeat(5) + "x".repeat(11) + "D".repeat(4);
        assertEquals("AAAAA…DDDD", RegexHound.redact(value));
    }

    @Test
    public void redactMasksShortValuesEntirely() {
        assertEquals("***", RegexHound.redact("short"));
    }

    @Test
    public void extractIpsFindsIpv4LiteralsIndependentOfSeverity() {
        List<String> ips = RegexHound.extractIps("hosts: 10.0.0.1, 256.1.1.1 (invalid), 192.168.1.1");

        assertTrue(ips.contains("10.0.0.1"));
        assertTrue(ips.contains("192.168.1.1"));
        assertFalse(ips.contains("256.1.1.1"));
    }

    @Test
    public void emptyOrNullTextYieldsNoFindings() {
        assertTrue(hound.scan(null, "response", "u", true).isEmpty());
        assertTrue(hound.scan("", "response", "u", true).isEmpty());
    }
}
