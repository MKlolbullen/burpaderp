package com.victor.reconloop;

import org.junit.Test;

import java.util.Optional;

import static org.junit.Assert.*;

public class NucleiTemplateBuilderTest {

    // ---- fromActiveFinding ----

    @Test
    public void sqliQueryParamProducesARegexBodyMatcherWithTheEncodedPayload() {
        Optional<NucleiTemplateBuilder.PocSpec> spec =
                NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t.example/item?id=1", "id");
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.REGEX, spec.get().matcherKind());
        assertEquals("body", spec.get().matcherPart());
        assertEquals("high", spec.get().severity());
        assertTrue(spec.get().targetUrl().contains("id=%27")); // ' url-encoded into the query
    }

    @Test
    public void sstiUsesTheDistinctiveProductMarkerAsAWordMatcher() {
        Optional<NucleiTemplateBuilder.PocSpec> spec =
                NucleiTemplateBuilder.fromActiveFinding("SSTI", "HIGH", "https://t.example/p?q=x", "q");
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.WORD, spec.get().matcherKind());
        assertEquals("rhs5439she", spec.get().matcherValue());
    }

    @Test
    public void openRedirectMatchesTheLocationHeader() {
        Optional<NucleiTemplateBuilder.PocSpec> spec =
                NucleiTemplateBuilder.fromActiveFinding("OpenRedirect", "MEDIUM", "https://t.example/go?next=/", "next");
        assertTrue(spec.isPresent());
        assertEquals("header", spec.get().matcherPart());
        assertTrue(spec.get().matcherValue().contains("rh-redirect.example.net"));
    }

    @Test
    public void outOfBandAndBlindClassesProduceNoTemplate() {
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SSRF", "HIGH", "https://t/x?u=1", "u").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("XSS-blind", "INFO", "https://t/x?u=1", "u").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("CMDi", "INFO", "https://t/x?u=1", "u").isEmpty());
    }

    @Test
    public void nonQueryParamInsertionPointsProduceNoTemplate() {
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x?u=1", "header:X-Forwarded-For").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "path[2]").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "json:/user/id").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(null, "HIGH", "https://t/x", "u").isEmpty());
    }

    // ---- build ----

    @Test
    public void buildEmitsAWellFormedTemplateSkeleton() {
        NucleiTemplateBuilder.PocSpec spec = NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t.example/item?id=1", "id").orElseThrow();
        String yaml = NucleiTemplateBuilder.build(spec);
        assertTrue(yaml.startsWith("id: recon-hound-sqli-"));
        assertTrue(yaml.contains("severity: high"));
        assertTrue(yaml.contains("author: recon-hound"));
        assertTrue(yaml.contains("http:"));
        assertTrue(yaml.contains("method: GET"));
        assertTrue(yaml.contains("type: regex"));
        assertTrue(yaml.contains("part: body"));
        assertTrue(yaml.contains("regex:"));
        assertTrue(yaml.contains("id=%27"));
    }

    // ---- withQueryParam ----

    @Test
    public void withQueryParamAddsReplacesAndPreservesOthers() {
        assertEquals("http://x/a?q=%27%20OR%201",
                NucleiTemplateBuilder.withQueryParam("http://x/a", "q", "' OR 1"));
        assertEquals("http://x/a?q=z&b=2",
                NucleiTemplateBuilder.withQueryParam("http://x/a?q=1&b=2", "q", "z"));
        assertEquals("http://x/a?b=2&q=z",
                NucleiTemplateBuilder.withQueryParam("http://x/a?b=2", "q", "z"));
    }

    @Test
    public void withQueryParamPreservesTheFragment() {
        assertEquals("http://x/a?q=z#frag",
                NucleiTemplateBuilder.withQueryParam("http://x/a#frag", "q", "z"));
    }

    // ---- yaml ----

    @Test
    public void yamlQuotesAndEscapes() {
        assertEquals("\"a\\\"b\"", NucleiTemplateBuilder.yaml("a\"b"));
        assertEquals("\"\"", NucleiTemplateBuilder.yaml(null));
    }
}
