package com.victor.reconloop;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AccessControlEngineTest {

    @Test
    public void volatileIdsDoNotHideEquivalentUnauthorizedResponse() {
        String privileged = """
                {"requestId":"550e8400-e29b-41d4-a716-446655440000",
                 "timestamp":"2026-10-17T12:00:00Z",
                 "user":{"id":42,"email":"victor@example.test","role":"admin"}}
                """;
        String replay = """
                {"timestamp":"2026-10-17T12:00:05Z",
                 "user":{"role":"admin","email":"victor@example.test","id":42},
                 "requestId":"123e4567-e89b-42d3-a456-426614174000"}
                """;

        AccessControlEngine.Result result =
                AccessControlEngine.classify(200, privileged, 200, replay);

        assertEquals(AccessControlEngine.Verdict.BYPASSED, result.verdict());
        assertEquals("HIGH", result.severity());
    }

    @Test
    public void sameStatusWithDifferentContentIsNotIdorByLengthAccident() {
        String privileged = "<html><h1>Admin dashboard</h1><p>export delete billing users</p></html>";
        String replay = "<html><h1>Public landing</h1><p>news docs contact careers</p></html>";

        AccessControlEngine.Result result =
                AccessControlEngine.classify(200, privileged, 200, replay);

        assertEquals(AccessControlEngine.Verdict.DIFFERENT, result.verdict());
        assertEquals("INFO", result.severity());
    }

    @Test
    public void partiallySimilarBodiesRemainAnalystReviewCandidates() {
        String privileged = "account profile invoices payments activity settings billing users admin secret";
        String replay = "account profile invoices payments activity settings billing users access denied";

        AccessControlEngine.Result result =
                AccessControlEngine.classify(200, privileged, 200, replay);

        assertEquals(AccessControlEngine.Verdict.PARTIAL, result.verdict());
        assertEquals("MEDIUM", result.severity());
        assertTrue(result.detail().contains("similar"));
    }

    @Test
    public void forbiddenReplayIsClearlyEnforced() {
        AccessControlEngine.Result result =
                AccessControlEngine.classify(200, "secret", 403, "forbidden");

        assertEquals(AccessControlEngine.Verdict.ENFORCED, result.verdict());
    }
}
