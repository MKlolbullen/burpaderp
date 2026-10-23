package com.victor.reconloop;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import static org.junit.Assert.*;

public class GfPatternLoaderTest {
    @Rule public TemporaryFolder temp = new TemporaryFolder();
    private Path directory(String name) throws Exception { return temp.newFolder(name).toPath(); }
    private void write(Path dir, String name, Object object) throws Exception {
        Files.writeString(dir.resolve(name + ".json"), Json.write(object));
    }
    @Test public void parsesCharacterClassesEscapesAndEveryArrayEntryWithActualJson() throws Exception {
        Path dir = directory("array");
        write(dir, "classes", Map.of("flags", "-Ei", "patterns", List.of("token_[a-z0-9]+", "quote=\"[A-Z]+\"", "path\\\\[a-z]+")));
        var loader = new GfPatternLoader(List.of(dir));
        assertEquals(3, loader.ruleCount()); assertEquals(List.of(), loader.diagnostics());
        var matches = loader.scan("TOKEN_abc123 quote=\"HELLO\" path\\file");
        assertEquals(3, matches.size());
        assertTrue(matches.stream().allMatch(m -> m.sensitive() && !m.displayValue().equals(m.value())));
    }
    @Test public void honorsSinglePatternPrecedenceFixedStringsAndDirectoryPriority() throws Exception {
        Path high = directory("high"), low = directory("low");
        write(high, "same", Map.of("flags", "-F", "pattern", "[literal]", "patterns", List.of("ignore-me")));
        write(low, "same", Map.of("pattern", "lower"));
        var loader = new GfPatternLoader(List.of(high, low));
        assertEquals(1, loader.packCount()); assertEquals(1, loader.scan("[literal]").size());
        assertTrue(loader.scan("ignore-me lower").isEmpty());
    }
    @Test public void malformedUnsupportedAndOversizedPacksHaveDiagnosticsWithoutRawContents() throws Exception {
        Path dir = directory("bad");
        Files.writeString(dir.resolve("duplicate.json"), "{\"pattern\":\"first\",\"pattern\":\"SYNTHETIC_SECRET\"}");
        Files.writeString(dir.resolve("large.json"), " ".repeat(GfPatternLoader.MAX_PACK_BYTES + 1));
        write(dir, "invalid-regex", Map.of("pattern", "[SYNTHETIC_SECRET"));
        write(dir, "inverted", Map.of("flags", "-v", "pattern", "secret"));
        var loader = new GfPatternLoader(List.of(dir));
        assertEquals(0, loader.packCount()); assertEquals(4, loader.diagnostics().size());
        assertFalse(loader.diagnostics().toString().contains("SYNTHETIC_SECRET"));
    }
    @Test public void zeroWidthAndLargeInputsCannotCreateUnboundedResults() throws Exception {
        Path dir = directory("bounded");
        write(dir, "zero", Map.of("pattern", "^"));
        write(dir, "tokens", Map.of("pattern", "token[0-9]{1,5}"));
        var loader = new GfPatternLoader(List.of(dir));
        assertTrue(loader.scan("x".repeat(GfPatternLoader.MAX_INPUT_CHARS) + "token123").isEmpty());
        String text = java.util.stream.IntStream.range(0,1000).mapToObj(i -> "token" + i).reduce("", (a,b) -> a + " " + b);
        assertEquals(GfPatternLoader.MAX_RULE_MATCHES, loader.scan(text).size());
    }
    @Test public void preservesHyphenAndUnderscoreTokenEndsAndAdjacentCandidates() {
        var loader = new GfPatternLoader(List.of(), true);
        String first = "AIza" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iLrU" + "-";
        String second = first.substring(0,first.length()-1) + "_";
        var matches = loader.scan(first + "," + second).stream().filter(m -> m.ruleId().equals("google-api-key")).toList();
        assertEquals(List.of(first, second), matches.stream().map(GfPatternLoader.GfMatch::value).toList());
        assertTrue(loader.scan("prefix" + first).stream().noneMatch(m -> m.ruleId().equals("google-api-key")));
        assertTrue(loader.scan(first + "EXTRA").stream().noneMatch(m -> m.ruleId().equals("google-api-key")));
    }
    @Test public void publicIdentifiersAreNotReportedAsSecretsAndJwtMustHaveJsonClaims() {
        var loader = new GfPatternLoader(List.of(), true);
        String publicKey = "6L" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iLrUoXaB";
        var captcha = loader.scan(publicKey).stream().filter(m -> m.ruleId().equals("google-recaptcha-site-key")).findFirst().orElseThrow();
        assertFalse(captcha.sensitive()); assertEquals("INFO", captcha.severity()); assertEquals(publicKey,captcha.displayValue());
        String notJson = "eyJub3QtanNvbiI" + "." + "bm90LWpzb24" + "." + "YWJjZGVmZ2hpamtsbW5vcA";
        assertTrue(loader.scan(notJson).stream().noneMatch(m -> m.ruleId().equals("jwt")));
    }
}
