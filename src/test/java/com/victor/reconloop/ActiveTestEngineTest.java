package com.victor.reconloop;

import org.junit.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.*;

public class ActiveTestEngineTest {

    // ---- detectSstiEval ----

    @Test
    public void detectsJinjaStyleEvaluation() {
        String body = "result: rhs5439she done";
        Optional<String> engine = ActiveTestEngine.detectSstiEval(body, "rhs{{7*777}}she");
        assertTrue(engine.isPresent());
        assertTrue(engine.get().toLowerCase().contains("jinja"));
    }

    @Test
    public void detectsElStyleEvaluation() {
        String body = "x=rhs5439she";
        Optional<String> engine = ActiveTestEngine.detectSstiEval(body, "rhs${7*777}she");
        assertTrue(engine.isPresent());
        assertTrue(engine.get().toLowerCase().contains("el/freemarker"));
    }

    @Test
    public void noEvaluationMarkerMeansEmpty() {
        assertTrue(ActiveTestEngine.detectSstiEval("nothing here", "rhs{{7*777}}she").isEmpty());
        assertTrue(ActiveTestEngine.detectSstiEval(null, "rhs{{7*777}}she").isEmpty());
    }

    // ---- survivingXssChars ----

    @Test
    public void findsAllFourSurvivingMetacharacters() {
        String token = "rhx1";
        String body = "before " + token + "<img>\"' after";
        assertEquals("<>\"'", ActiveTestEngine.survivingXssChars(body, token));
    }

    @Test
    public void encodedMetacharactersDoNotSurvive() {
        String token = "rhx1";
        String body = "before " + token + "&lt;img&gt;&quot;&#39; after";
        assertEquals("", ActiveTestEngine.survivingXssChars(body, token));
    }

    @Test
    public void tokenAbsentMeansNoSurvivors() {
        assertEquals("", ActiveTestEngine.survivingXssChars("no token here", "rhx1"));
        assertEquals("", ActiveTestEngine.survivingXssChars(null, "rhx1"));
    }

    // ---- fingerprintWaf ----

    @Test
    public void identifiesCloudflareFromBodySignature() {
        Optional<String> waf = ActiveTestEngine.fingerprintWaf(403, "Attention Required! | Cloudflare", null);
        assertEquals(Optional.of("Cloudflare"), waf);
    }

    @Test
    public void identifiesAkamaiFromServerHeader() {
        Optional<String> waf = ActiveTestEngine.fingerprintWaf(403, "blocked", "AkamaiGHost");
        assertEquals(Optional.of("Akamai"), waf);
    }

    @Test
    public void genericBlockStatusWithoutSignatureIsStillFlagged() {
        Optional<String> waf = ActiveTestEngine.fingerprintWaf(406, "nope", null);
        assertTrue(waf.isPresent());
        assertTrue(waf.get().contains("generic"));
    }

    @Test
    public void ordinaryResponseIsNotFingerprinted() {
        assertTrue(ActiveTestEngine.fingerprintWaf(200, "<html>ok</html>", "nginx").isEmpty());
    }

    // ---- detectOpenRedirect ----

    @Test
    public void redirectToMarkerHostViaHttpsIsDetected() {
        Optional<String> hit = ActiveTestEngine.detectOpenRedirect(302, "https://rh-redirect.example.net/", "rh-redirect.example.net");
        assertTrue(hit.isPresent());
    }

    @Test
    public void redirectToMarkerHostViaSchemeRelativeIsDetected() {
        Optional<String> hit = ActiveTestEngine.detectOpenRedirect(301, "//rh-redirect.example.net/path", "rh-redirect.example.net");
        assertTrue(hit.isPresent());
    }

    @Test
    public void markerOnlyInQueryValueIsNotFalselyFlagged() {
        Optional<String> hit = ActiveTestEngine.detectOpenRedirect(302, "/login?next=rh-redirect.example.net", "rh-redirect.example.net");
        assertTrue(hit.isEmpty());
    }

    @Test
    public void nonRedirectStatusIsIgnored() {
        assertTrue(ActiveTestEngine.detectOpenRedirect(200, "https://rh-redirect.example.net/", "rh-redirect.example.net").isEmpty());
    }

    @Test
    public void missingLocationHeaderIsIgnored() {
        assertTrue(ActiveTestEngine.detectOpenRedirect(302, null, "rh-redirect.example.net").isEmpty());
    }

    // ---- encodeCorrelation / decodeCorrelation ----

    @Test
    public void correlationRoundTripsThroughEncodeDecode() {
        String encoded = ActiveTestEngine.encodeCorrelation("SSRF", "url", "https://example.com/a|b");
        String[] decoded = ActiveTestEngine.decodeCorrelation(encoded);
        assertArrayEquals(new String[]{"SSRF", "url", "https://example.com/a|b"}, decoded);
    }

    @Test
    public void decodeRejectsUnrelatedCustomData() {
        assertNull(ActiveTestEngine.decodeCorrelation("something-else"));
        assertNull(ActiveTestEngine.decodeCorrelation(null));
    }

    // ---- containsSqlError ----

    @Test
    public void recognisesMysqlErrorSignature() {
        assertTrue(ActiveTestEngine.containsSqlError("You have an error in your SQL syntax; check the manual"));
    }

    @Test
    public void recognisesOracleErrorCode() {
        assertTrue(ActiveTestEngine.containsSqlError("ORA-00933: SQL command not properly ended"));
    }

    @Test
    public void recognisesMssqlOdbcSignature() {
        assertTrue(ActiveTestEngine.containsSqlError("Microsoft OLE DB Provider for ODBC Drivers error '80040e14'"));
    }

    @Test
    public void ordinaryBodyHasNoSqlErrorSignature() {
        assertFalse(ActiveTestEngine.containsSqlError("<html><body>Welcome back</body></html>"));
        assertFalse(ActiveTestEngine.containsSqlError(null));
        assertFalse(ActiveTestEngine.containsSqlError(""));
    }

    // ---- closeEnough ----

    @Test
    public void identicalBodiesAreCloseEnough() {
        assertTrue(ActiveTestEngine.closeEnough("same page content", "same page content"));
    }

    @Test
    public void slightlyDifferentLengthWithinToleranceIsCloseEnough() {
        String a = "x".repeat(1000);
        String b = "x".repeat(1004);
        assertTrue(ActiveTestEngine.closeEnough(a, b));
    }

    @Test
    public void substantiallyDifferentLengthIsNotCloseEnough() {
        String a = "x".repeat(1000);
        String b = "x".repeat(50);
        assertFalse(ActiveTestEngine.closeEnough(a, b));
    }

    @Test
    public void nullBodiesAreNeverCloseEnough() {
        assertFalse(ActiveTestEngine.closeEnough(null, "x"));
        assertFalse(ActiveTestEngine.closeEnough("x", null));
    }

    // ---- looksBooleanBased ----

    @Test
    public void classicBooleanBlindDivergenceIsDetected() {
        String baseline = "<html>1 user found: alice</html>";
        String trueBody = "<html>1 user found: alice</html>";
        String falseBody = "<html>0 users found</html>";
        assertTrue(ActiveTestEngine.looksBooleanBased(baseline, trueBody, falseBody));
    }

    @Test
    public void identicalTrueAndFalseResponsesAreNotBooleanBlind() {
        String baseline = "<html>page</html>";
        String trueBody = "<html>page</html>";
        String falseBody = "<html>page</html>";
        assertFalse(ActiveTestEngine.looksBooleanBased(baseline, trueBody, falseBody));
    }

    @Test
    public void trueDivergingFromBaselineIsNotBooleanBlind() {
        String baseline = "<html>1 user found: alice</html>";
        String trueBody = "<html>error</html>";
        String falseBody = "<html>error</html>";
        assertFalse(ActiveTestEngine.looksBooleanBased(baseline, trueBody, falseBody));
    }

    @Test
    public void nullBodiesProduceNoBooleanBlindVerdict() {
        assertFalse(ActiveTestEngine.looksBooleanBased(null, "a", "b"));
        assertFalse(ActiveTestEngine.looksBooleanBased("a", null, "b"));
        assertFalse(ActiveTestEngine.looksBooleanBased("a", "b", null));
    }

    // ---- looksTimeBased ----

    @Test
    public void fullFiveSecondDelayIsDetected() {
        assertTrue(ActiveTestEngine.looksTimeBased(150, 5100, 5));
    }

    @Test
    public void delayWithinToleranceIsStillDetected() {
        assertTrue(ActiveTestEngine.looksTimeBased(100, 4200, 5)); // 4.1s delta, within 1s tolerance of 5s
    }

    @Test
    public void noMeaningfulDelayIsNotDetected() {
        assertFalse(ActiveTestEngine.looksTimeBased(150, 300, 5));
    }

    @Test
    public void slowBaselineDoesNotFalselyTriggerOnAbsoluteTimeAlone() {
        // Both requests are slow (e.g. a loaded server), but there's no meaningful delta.
        assertFalse(ActiveTestEngine.looksTimeBased(4800, 4900, 5));
    }

    // ---- craftCorsProbeOrigins ----

    @Test
    public void alwaysIncludesArbitraryAndNullOriginsRegardlessOfHost() {
        List<String> withHost = ActiveTestEngine.craftCorsProbeOrigins("app.example.com");
        List<String> withoutHost = ActiveTestEngine.craftCorsProbeOrigins(null);
        for (List<String> origins : List.of(withHost, withoutHost)) {
            assertTrue(origins.contains("https://recon-hound-cors-probe.invalid"));
            assertTrue(origins.contains("null"));
        }
    }

    @Test
    public void hostDependentBypassPayloadsAreOnlyAddedWhenHostIsKnown() {
        List<String> withHost = ActiveTestEngine.craftCorsProbeOrigins("app.example.com");
        assertTrue(withHost.contains("https://app.example.com.recon-hound-probe.invalid"));
        assertTrue(withHost.contains("https://evilapp.example.com"));
        assertTrue(withHost.contains("http://app.example.com"));

        assertEquals(2, ActiveTestEngine.craftCorsProbeOrigins(null).size());
        assertEquals(2, ActiveTestEngine.craftCorsProbeOrigins("").size());
    }

    @Test
    public void noSeparatorPrefixBypassPayloadWouldSatisfyANaiveEndsWithCheck() {
        List<String> origins = ActiveTestEngine.craftCorsProbeOrigins("app.example.com");
        String bypass = origins.stream().filter(o -> o.equals("https://evilapp.example.com")).findFirst().orElseThrow();
        // The exact bug this payload targets: an endsWith(".../app.example.com") check with no dot-boundary requirement.
        assertTrue(bypass.endsWith("app.example.com"));
    }

    // ---- corsReflectsOrigin ----

    @Test
    public void reflectsWhenAcaoExactlyMatchesTheSentOrigin() {
        assertTrue(ActiveTestEngine.corsReflectsOrigin("https://evil.example", "https://evil.example"));
    }

    @Test
    public void reflectsIsCaseInsensitiveAndTrimsWhitespace() {
        assertTrue(ActiveTestEngine.corsReflectsOrigin("NULL", " null "));
    }

    @Test
    public void doesNotReflectWhenAcaoDiffersFromSentOrigin() {
        assertFalse(ActiveTestEngine.corsReflectsOrigin("https://evil.example", "https://real-app.example"));
    }

    @Test
    public void doesNotReflectWhenAcaoOrOriginIsMissing() {
        assertFalse(ActiveTestEngine.corsReflectsOrigin(null, "https://evil.example"));
        assertFalse(ActiveTestEngine.corsReflectsOrigin("https://evil.example", null));
    }

    // ---- hostOf ----

    @Test
    public void extractsHostFromAnOrdinaryUrl() {
        assertEquals("app.example.com", ActiveTestEngine.hostOf("https://app.example.com/path?x=1"));
    }

    @Test
    public void returnsNullForUnparsableOrMissingUrls() {
        assertNull(ActiveTestEngine.hostOf(null));
        assertNull(ActiveTestEngine.hostOf("not a url at all :: /// "));
    }

    // ---- looksLikeSensitiveEndpoint ----

    @Test
    public void recognisesCommonSensitiveEndpointShapes() {
        assertTrue(ActiveTestEngine.looksLikeSensitiveEndpoint("https://app.example.com/login"));
        assertTrue(ActiveTestEngine.looksLikeSensitiveEndpoint("https://app.example.com/account/password/reset"));
        assertTrue(ActiveTestEngine.looksLikeSensitiveEndpoint("https://app.example.com/api/v1/otp/verify"));
        assertTrue(ActiveTestEngine.looksLikeSensitiveEndpoint("https://app.example.com/signup"));
    }

    @Test
    public void ordinaryEndpointsAreNotSensitive() {
        assertFalse(ActiveTestEngine.looksLikeSensitiveEndpoint("https://app.example.com/products/42"));
        assertFalse(ActiveTestEngine.looksLikeSensitiveEndpoint(null));
    }

    // ---- anyRateLimited ----

    @Test
    public void statusCode429IsRecognisedAsRateLimited() {
        assertTrue(ActiveTestEngine.anyRateLimited(List.of(200, 200, 429, 200), List.of("", "", "", ""), List.of("", "", "", "")));
    }

    @Test
    public void retryAfterHeaderIsRecognisedAsRateLimited() {
        assertTrue(ActiveTestEngine.anyRateLimited(
                List.of(200, 503), List.of("ok", "slow down"), Arrays.asList(null, "30")));
    }

    @Test
    public void lockoutWordingInBodyIsRecognisedAsRateLimited() {
        assertTrue(ActiveTestEngine.anyRateLimited(
                List.of(200, 200), List.of("ok", "Too many attempts, please try again later."), List.of("", "")));
    }

    @Test
    public void allSuccessfulResponsesWithNoSignalAreNotRateLimited() {
        assertFalse(ActiveTestEngine.anyRateLimited(
                List.of(200, 200, 200, 200), List.of("ok", "ok", "ok", "ok"), List.of("", "", "", "")));
    }

    @Test
    public void emptyBurstIsNotRateLimited() {
        assertFalse(ActiveTestEngine.anyRateLimited(List.of(), List.of(), List.of()));
        assertFalse(ActiveTestEngine.anyRateLimited(null, null, null));
    }

    // ---- detectPathTraversal ----

    @Test
    public void unixPasswdCanaryAbsentFromBaselineIsReported() {
        String body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
        Optional<String> hit = ActiveTestEngine.detectPathTraversal(body, "Welcome, please log in.");
        assertTrue(hit.isPresent());
        assertTrue(hit.get().contains("/etc/passwd"));
    }

    @Test
    public void passwdLineWithShadowedPasswordStillMatches() {
        // The password field may be "x", "*", or a hash; the UID:GID 0:0 pin is what confirms root.
        assertTrue(ActiveTestEngine.detectPathTraversal("root:*:0:0:Charlie &:/root:/bin/csh", "").isPresent());
    }

    @Test
    public void windowsWinIniCanaryIsReportedCaseInsensitively() {
        Optional<String> hit = ActiveTestEngine.detectPathTraversal("; for 16-bit app support\n[FONTS]\n", "home page");
        assertTrue(hit.isPresent());
        assertTrue(hit.get().contains("win.ini"));
    }

    @Test
    public void canaryPresentInBaselineIsNotReported() {
        // A page that legitimately contains a passwd-looking line must not be flagged as a file read.
        String same = "example config: root:x:0:0:svc account\n";
        assertTrue(ActiveTestEngine.detectPathTraversal(same, same).isEmpty());
    }

    @Test
    public void noCanaryOrEmptyBodyIsNotReported() {
        assertTrue(ActiveTestEngine.detectPathTraversal("nothing sensitive here", "baseline").isEmpty());
        assertTrue(ActiveTestEngine.detectPathTraversal("", "baseline").isEmpty());
        assertTrue(ActiveTestEngine.detectPathTraversal(null, "baseline").isEmpty());
    }

    @Test
    public void ordinaryTextContainingTheWordRootIsNotAFalsePositive() {
        // "root" as a word, without the UID:GID 0:0 structure, must not match.
        assertTrue(ActiveTestEngine.detectPathTraversal(
                "The root cause of the issue was a misconfiguration.", "").isEmpty());
    }

    // ---- containsNoSqlError ----

    @Test
    public void mongoDriverErrorsAreRecognised() {
        assertTrue(ActiveTestEngine.containsNoSqlError("MongoError: unknown operator: $wheree"));
        assertTrue(ActiveTestEngine.containsNoSqlError("MongoServerError: E11000 duplicate key error collection"));
        assertTrue(ActiveTestEngine.containsNoSqlError("CastError: Cast to ObjectId failed for value \"x\""));
        assertTrue(ActiveTestEngine.containsNoSqlError("Uncaught BSONError: bad BSON document"));
        assertTrue(ActiveTestEngine.containsNoSqlError("ValidationError from Mongoose schema"));
    }

    @Test
    public void reflectedWhereOperatorCountsAsANoSqlSignature() {
        assertTrue(ActiveTestEngine.containsNoSqlError("SyntaxError in $where clause near return true"));
    }

    @Test
    public void cleanOrEmptyBodyIsNotANoSqlError() {
        assertFalse(ActiveTestEngine.containsNoSqlError("Welcome back, your dashboard is ready."));
        assertFalse(ActiveTestEngine.containsNoSqlError(""));
        assertFalse(ActiveTestEngine.containsNoSqlError(null));
    }

    @Test
    public void aPlainSqlErrorIsNotMistakenForNoSql() {
        assertFalse(ActiveTestEngine.containsNoSqlError("ORA-00933: SQL command not properly ended"));
        assertFalse(ActiveTestEngine.containsNoSqlError("You have an error in your SQL syntax"));
    }
}
