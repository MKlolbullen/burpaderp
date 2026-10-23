package com.victor.reconloop;

import org.junit.Test;

import java.util.Optional;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class NucleiTemplateBuilderTest {

    // Built from the shared markers the engine actually writes, so a reworded marker moves the engine,
    // the builder gate and these fixtures together instead of leaving the tests holding a stale copy.
    private static final String SQLI_ERROR_EV =
            "Injecting a single quote produced a " + DetectionSignatures.SQL_ERROR_EVIDENCE
                    + " not present in the baseline response";
    private static final String SSTI_JINJA_EV =
            "Template arithmetic evaluated (7*777=5439) via " + DetectionSignatures.SSTI_JINJA_FAMILY;

    // ---- fromActiveFinding ----

    @Test
    public void errorBasedSqliQueryParamProducesARegexBodyMatcherWithTheEncodedPayload() {
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t.example/item?id=1", "id", SQLI_ERROR_EV);
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.REGEX, spec.get().matcherKind());
        assertEquals("body", spec.get().matcherPart());
        assertEquals("high", spec.get().severity());
        assertTrue(spec.get().targetUrl().contains("id=%27")); // ' url-encoded into the query
        // The PoC matches on the SAME signature set the engine confirmed with — not a narrower copy.
        assertEquals(DetectionSignatures.SQL_ERROR_REGEX, spec.get().matcherValue());
    }

    @Test
    public void booleanOrTimeBasedSqliProducesNoTemplate() {
        // These confirmations aren't reproduced by an error-signature body matcher.
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x?id=1", "id",
                "Boolean-based blind: the always-true condition matches the baseline response").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x?id=1", "id",
                "Repeated time-based blind signal for payload ' OR SLEEP(5)-- -").isEmpty());
    }

    @Test
    public void noSqliProducesARegexBodyMatcherFromTheSharedSignatures() {
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "NoSQLi", "HIGH", "https://t.example/api?q=1", "q",
                "Injecting '\" produced a NoSQL datastore error signature not present in the baseline response");
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.REGEX, spec.get().matcherKind());
        assertEquals("body", spec.get().matcherPart());
        assertEquals(DetectionSignatures.NOSQL_ERROR_REGEX, spec.get().matcherValue());
    }

    /**
     * The regression that pins findings #1/#2: a PoC must match on exactly what the engine confirmed on.
     * For every signature the engine flags, the emitted PoC matcher must flag it too — the old hand-copied
     * matchers had drifted to a subset, so these signatures confirmed a finding but produced a PoC whose
     * matcher could never match.
     */
    @Test
    public void emittedMatchersCoverEverySignatureTheEngineConfirmsOn() {
        String sqlMatcher = NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t/x?id=1", "id", SQLI_ERROR_EV).orElseThrow().matcherValue();
        Pattern sqlPoc = Pattern.compile(sqlMatcher);
        for (String sig : new String[]{
                "Incorrect syntax near ')'",                       // MSSQL — omitted by the old matcher
                "System.Data.SqlClient.SqlException: timeout",     // .NET  — omitted by the old matcher
                "SQLSTATE[42000]: Syntax error",                   // PDO   — omitted by the old matcher
                "Warning: pg_query(): query failed",               // PostgreSQL — omitted by the old matcher
                "You have an error in your SQL syntax"}) {         // MySQL — was covered
            assertTrue("engine confirms: " + sig, ActiveTestEngine.containsSqlError(sig));
            assertTrue("PoC must reproduce: " + sig, sqlPoc.matcher(sig).find());
        }

        String noSqlMatcher = NucleiTemplateBuilder.fromActiveFinding(
                "NoSQLi", "HIGH", "https://t/x?q=1", "q",
                "Injecting '\" produced a NoSQL datastore error signature not present in the baseline response")
                .orElseThrow().matcherValue();
        Pattern noSqlPoc = Pattern.compile(noSqlMatcher);
        for (String sig : new String[]{
                "CastError: Cast to ObjectId failed",              // omitted by the old matcher
                "Uncaught couchdberror while querying",            // omitted by the old matcher
                "ValidationError from Mongoose schema",            // omitted by the old matcher
                "MongoServerError: E11000 duplicate key"}) {       // was covered
            assertTrue("engine confirms: " + sig, ActiveTestEngine.containsNoSqlError(sig));
            assertTrue("PoC must reproduce: " + sig, noSqlPoc.matcher(sig).find());
        }
    }

    @Test
    public void jinjaSstiUsesTheDistinctiveProductMarkerAsAWordMatcher() {
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "SSTI", "HIGH", "https://t.example/p?q=x", "q", SSTI_JINJA_EV);
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.WORD, spec.get().matcherKind());
        assertEquals("rhs5439she", spec.get().matcherValue());
    }

    @Test
    public void nonBraceSstiFamilyProducesNoTemplate() {
        // A ${...} / #{...} / <%=%> engine won't evaluate the {{7*777}} payload.
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SSTI", "HIGH", "https://t/p?q=x", "q",
                "Template arithmetic evaluated (7*777=5439) via EL/Freemarker ${...}").isEmpty());
    }

    @Test
    public void nestedBraceSstiFamilyProducesNoTemplate() {
        // The nested ${{...}} family's engine does not evaluate the plain {{7*777}} payload, and its label
        // contains "{{" — so a bare-substring gate would wrongly emit a non-reproducing PoC. It must not.
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SSTI", "HIGH", "https://t/p?q=x", "q",
                "Template arithmetic evaluated (7*777=5439) via nested ${{...}}").isEmpty());
    }

    @Test
    public void openRedirectMatchesTheLocationHeader() {
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "OpenRedirect", "MEDIUM", "https://t.example/go?next=/", "next", "Redirect Location points to attacker host");
        assertTrue(spec.isPresent());
        assertEquals("header", spec.get().matcherPart());
        assertTrue(spec.get().matcherValue().contains("rh-redirect.example.net"));
    }

    @Test
    public void outOfBandAndBlindClassesProduceNoTemplate() {
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SSRF", "HIGH", "https://t/x?u=1", "u", "ev").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("XSS-blind", "INFO", "https://t/x?u=1", "u", "ev").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("CMDi", "INFO", "https://t/x?u=1", "u", "ev").isEmpty());
    }

    @Test
    public void nonQueryParamInsertionPointsProduceNoTemplate() {
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x?u=1", "header:X-Forwarded-For", SQLI_ERROR_EV).isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "path[2]", SQLI_ERROR_EV).isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "json:/user/id", SQLI_ERROR_EV).isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "", SQLI_ERROR_EV).isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(null, "HIGH", "https://t/x", "u", "ev").isEmpty());
    }

    // ---- build ----

    @Test
    public void buildEmitsAWellFormedTemplateSkeleton() {
        NucleiTemplateBuilder.PocSpec spec = NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t.example/item?id=1", "id", SQLI_ERROR_EV).orElseThrow();
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
