package com.victor.reconloop;

import org.junit.Test;

import java.util.Optional;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class NucleiTemplateBuilderTest {

    // ---- fromActiveFinding: gating is on the structured vector, not evidence prose ----

    @Test
    public void errorBasedSqliQueryParamProducesARegexBodyMatcherWithTheEncodedPayload() {
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t.example/item?id=1", "id", ConfirmationVector.SQL_ERROR, "'");
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
        // These vectors aren't reproduced by an error-signature body matcher.
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t/x?id=1", "id", ConfirmationVector.SQL_BOOLEAN, "' OR '1'='1'-- -").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t/x?id=1", "id", ConfirmationVector.SQL_TIME, "' OR SLEEP(5)-- -").isEmpty());
    }

    @Test
    public void noSqliFiresTheExactConfirmingProbeAndTheSharedSignatureMatcher() {
        // The engine tries several NoSQL probes; the PoC must fire the one that actually errored.
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "NoSQLi", "HIGH", "https://t.example/api?q=1", "q", ConfirmationVector.NOSQL_ERROR, "[$ne]");
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.REGEX, spec.get().matcherKind());
        assertEquals("body", spec.get().matcherPart());
        assertEquals(DetectionSignatures.NOSQL_ERROR_REGEX, spec.get().matcherValue());
        assertTrue(spec.get().targetUrl().contains("q=%5B%24ne%5D")); // the exact confirming payload, encoded
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
                "SQLi", "HIGH", "https://t/x?id=1", "id", ConfirmationVector.SQL_ERROR, "'").orElseThrow().matcherValue();
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
                "NoSQLi", "HIGH", "https://t/x?q=1", "q", ConfirmationVector.NOSQL_ERROR, "[$ne]")
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
                "SSTI", "HIGH", "https://t.example/p?q=x", "q", ConfirmationVector.SSTI_BRACE, "rhs{{7*777}}she");
        assertTrue(spec.isPresent());
        assertEquals(NucleiTemplateBuilder.MatcherKind.WORD, spec.get().matcherKind());
        assertEquals("rhs5439she", spec.get().matcherValue());
    }

    @Test
    public void nonBraceAndNestedSstiFamiliesProduceNoTemplate() {
        // A ${...}/#{...}/<%=%> engine, and the nested ${{...}} family, do not evaluate the {{7*777}}
        // payload — all carry SSTI_OTHER, and none may emit a (non-reproducing) template.
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(
                "SSTI", "HIGH", "https://t/p?q=x", "q", ConfirmationVector.SSTI_OTHER, "rhs${7*777}she").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(
                "SSTI", "HIGH", "https://t/p?q=x", "q", ConfirmationVector.SSTI_OTHER, "rhs${{7*777}}she").isEmpty());
    }

    @Test
    public void openRedirectMatchesTheLocationHeader() {
        // OpenRedirect carries no structured vector (single mechanism); it keys off the class alone.
        Optional<NucleiTemplateBuilder.PocSpec> spec = NucleiTemplateBuilder.fromActiveFinding(
                "OpenRedirect", "MEDIUM", "https://t.example/go?next=/", "next", null, null);
        assertTrue(spec.isPresent());
        assertEquals("header", spec.get().matcherPart());
        assertTrue(spec.get().matcherValue().contains("rh-redirect.example.net"));
    }

    @Test
    public void outOfBandAndBlindClassesProduceNoTemplate() {
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SSRF", "HIGH", "https://t/x?u=1", "u", null, null).isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("XSS-blind", "INFO", "https://t/x?u=1", "u", null, null).isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("CMDi", "INFO", "https://t/x?u=1", "u", null, null).isEmpty());
    }

    @Test
    public void sqliWithoutTheErrorVectorProducesNoTemplate() {
        // A SQLi finding that somehow carries no error vector must not emit (would not reproduce).
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x?id=1", "id", null, "'").isEmpty());
    }

    @Test
    public void nonQueryParamInsertionPointsProduceNoTemplate() {
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x?u=1", "header:X-Forwarded-For", ConfirmationVector.SQL_ERROR, "'").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "path[2]", ConfirmationVector.SQL_ERROR, "'").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "json:/user/id", ConfirmationVector.SQL_ERROR, "'").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding("SQLi", "HIGH", "https://t/x", "", ConfirmationVector.SQL_ERROR, "'").isEmpty());
        assertTrue(NucleiTemplateBuilder.fromActiveFinding(null, "HIGH", "https://t/x", "u", null, null).isEmpty());
    }

    // ---- build ----

    @Test
    public void buildEmitsAWellFormedTemplateSkeleton() {
        NucleiTemplateBuilder.PocSpec spec = NucleiTemplateBuilder.fromActiveFinding(
                "SQLi", "HIGH", "https://t.example/item?id=1", "id", ConfirmationVector.SQL_ERROR, "'").orElseThrow();
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
