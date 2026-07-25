package com.victor.reconloop;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class SqlmapClientTest {

    private static final SqlmapClient.Target GET_TARGET =
            new SqlmapClient.Target("https://app.example.com/search?q=1", "GET", "q", null, null);

    // ---- buildArgs ----

    @Test
    public void alwaysIncludesBatchAndTargetUrl() {
        List<String> args = SqlmapClient.buildArgs(GET_TARGET, 1, 1, null, null);
        assertTrue(args.contains("--batch"));
        int urlFlag = args.indexOf("-u");
        assertTrue(urlFlag >= 0);
        assertEquals("https://app.example.com/search?q=1", args.get(urlFlag + 1));
    }

    @Test
    public void includesParameterFlagWhenParameterGiven() {
        List<String> args = SqlmapClient.buildArgs(GET_TARGET, 1, 1, null, null);
        int paramFlag = args.indexOf("-p");
        assertTrue(paramFlag >= 0);
        assertEquals("q", args.get(paramFlag + 1));
    }

    @Test
    public void omitsParameterFlagWhenParameterIsBlank() {
        SqlmapClient.Target target = new SqlmapClient.Target("https://app.example.com/x", "GET", "", null, null);
        assertFalse(SqlmapClient.buildArgs(target, 1, 1, null, null).contains("-p"));
    }

    @Test
    public void includesDataFlagOnlyForPostWithABody() {
        SqlmapClient.Target post = new SqlmapClient.Target(
                "https://app.example.com/login", "POST", "username", "username=admin&password=x", null);
        List<String> args = SqlmapClient.buildArgs(post, 1, 1, null, null);
        assertTrue(args.contains("--data=username=admin&password=x"));
    }

    @Test
    public void omitsDataFlagForGetEvenIfBodyProvided() {
        SqlmapClient.Target get = new SqlmapClient.Target("https://app.example.com/x", "GET", "q", "should-be-ignored", null);
        List<String> args = SqlmapClient.buildArgs(get, 1, 1, null, null);
        assertFalse(args.stream().anyMatch(a -> a.startsWith("--data=")));
    }

    @Test
    public void includesCookieFlagWhenCookieHeaderGiven() {
        SqlmapClient.Target target = new SqlmapClient.Target(
                "https://app.example.com/x", "GET", "q", null, "session=abc123");
        assertTrue(SqlmapClient.buildArgs(target, 1, 1, null, null).contains("--cookie=session=abc123"));
    }

    @Test
    public void levelAndRiskAreClampedToSqlmapsValidRanges() {
        List<String> args = SqlmapClient.buildArgs(GET_TARGET, 99, -5, null, null);
        assertTrue(args.contains("--level=5"));
        assertTrue(args.contains("--risk=1"));
    }

    @Test
    public void includesTechniqueFlagWhenGiven() {
        assertTrue(SqlmapClient.buildArgs(GET_TARGET, 1, 1, "BEUST", null).contains("--technique=BEUST"));
    }

    @Test
    public void omitsTechniqueFlagWhenBlank() {
        assertFalse(SqlmapClient.buildArgs(GET_TARGET, 1, 1, "  ", null).stream().anyMatch(a -> a.startsWith("--technique=")));
    }

    @Test
    public void appendsExtraArgsAsSeparateTokens() {
        List<String> args = SqlmapClient.buildArgs(GET_TARGET, 1, 1, null, "--dump --threads=4");
        assertTrue(args.contains("--dump"));
        assertTrue(args.contains("--threads=4"));
    }

    @Test
    public void defaultArgsNeverIncludeDestructiveFlagsUnlessExplicitlyRequested() {
        List<String> args = SqlmapClient.buildArgs(GET_TARGET, 1, 1, null, null);
        for (String destructive : List.of("--dump", "--os-shell", "--sql-shell", "--os-cmd", "--file-write")) {
            assertFalse(args.contains(destructive));
        }
    }

    // ---- clamp ----

    @Test
    public void clampKeepsInRangeValuesUnchanged() {
        assertEquals(3, SqlmapClient.clamp(3, 1, 5));
    }

    @Test
    public void clampBoundsOutOfRangeValues() {
        assertEquals(1, SqlmapClient.clamp(0, 1, 5));
        assertEquals(5, SqlmapClient.clamp(10, 1, 5));
    }

    // ---- looksVulnerable / extractInjectionTypes ----

    private static final String VULNERABLE_OUTPUT = """
            sqlmap identified the following injection point(s):
            Parameter: q (GET)
                Type: boolean-based blind
                Title: AND boolean-based blind - WHERE or HAVING clause
                Payload: q=1 AND 1=1

                Type: time-based blind
                Title: MySQL >= 5.0.12 AND time-based blind
                Payload: q=1 AND SLEEP(5)
            """;

    @Test
    public void recognisesConfirmedInjectionOutput() {
        assertTrue(SqlmapClient.looksVulnerable(VULNERABLE_OUTPUT));
    }

    @Test
    public void doesNotFalselyRecogniseUnrelatedOutputAsVulnerable() {
        assertFalse(SqlmapClient.looksVulnerable("usage: sqlmap [options]"));
        assertFalse(SqlmapClient.looksVulnerable(null));
    }

    @Test
    public void extractsEachDistinctInjectionType() {
        List<String> types = SqlmapClient.extractInjectionTypes(VULNERABLE_OUTPUT);
        assertEquals(List.of("boolean-based blind", "time-based blind"), types);
    }

    @Test
    public void extractInjectionTypesReturnsEmptyForNoMatches() {
        assertTrue(SqlmapClient.extractInjectionTypes("nothing here").isEmpty());
        assertTrue(SqlmapClient.extractInjectionTypes(null).isEmpty());
    }

    // ---- looksNotInjectable ----

    @Test
    public void recognisesTheConfidentNegativePhrase() {
        assertTrue(SqlmapClient.looksNotInjectable(
                "all tested parameters do not appear to be injectable."));
    }

    @Test
    public void doesNotTreatSilenceOrErrorsAsAConfidentNegative() {
        assertFalse(SqlmapClient.looksNotInjectable("connection timed out"));
        assertFalse(SqlmapClient.looksNotInjectable(null));
    }
}
