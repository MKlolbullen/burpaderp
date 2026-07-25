package com.victor.reconloop;

import org.junit.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.*;

public class OAuthEngineTest {

    private static Map<String, String> authRequest(Map<String, String> extra) {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("response_type", "code");
        params.put("client_id", "abc123");
        params.put("redirect_uri", "https://app.example/callback");
        params.put("state", "xyz789");
        params.put("code_challenge", "abcdefgh");
        params.putAll(extra);
        return params;
    }

    private static boolean hasNote(List<OAuthEngine.Note> notes, String nameContains) {
        return notes.stream().anyMatch(n -> n.name().toLowerCase().contains(nameContains.toLowerCase()));
    }

    @Test
    public void wellFormedAuthorizationRequestProducesNoNotes() {
        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://as.example/authorize", authRequest(Map.of()));
        assertTrue(notes.isEmpty());
    }

    @Test
    public void implicitFlowIsFlagged() {
        Map<String, String> params = authRequest(Map.of());
        params.put("response_type", "token");
        params.remove("code_challenge"); // PKCE doesn't apply to pure implicit flow

        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://as.example/authorize", params);

        assertTrue(hasNote(notes, "implicit/hybrid flow"));
        assertFalse(hasNote(notes, "missing pkce")); // must not fire for a flow with no code at all
    }

    @Test
    public void idTokenHybridResponseTypeIsAlsoTreatedAsImplicit() {
        Map<String, String> params = authRequest(Map.of());
        params.put("response_type", "code id_token");

        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://as.example/authorize", params);

        assertTrue(hasNote(notes, "implicit/hybrid flow"));
    }

    @Test
    public void missingStateIsFlaggedMedium() {
        Map<String, String> params = authRequest(Map.of());
        params.remove("state");

        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://as.example/authorize", params);

        OAuthEngine.Note note = notes.stream().filter(n -> n.name().toLowerCase().contains("missing state")).findFirst().orElseThrow();
        assertEquals("MEDIUM", note.severity());
    }

    @Test
    public void blankStateIsTreatedAsMissing() {
        Map<String, String> params = authRequest(Map.of());
        params.put("state", "   ");

        assertTrue(hasNote(OAuthEngine.analyze("https://as.example/authorize", params), "missing state"));
    }

    @Test
    public void missingPkceOnCodeFlowIsFlagged() {
        Map<String, String> params = authRequest(Map.of());
        params.remove("code_challenge");

        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://as.example/authorize", params);

        assertTrue(hasNote(notes, "missing pkce"));
    }

    @Test
    public void tokenInUrlIsFlaggedEvenOutsideAnAuthorizationRequest() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("access_token", "some-token-value");

        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://app.example/callback", params);

        assertTrue(hasNote(notes, "token present in the url"));
    }

    @Test
    public void clientSecretInUrlIsFlaggedHigh() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("client_secret", "s3cr3t-value");

        List<OAuthEngine.Note> notes = OAuthEngine.analyze("https://app.example/token", params);

        OAuthEngine.Note note = notes.stream().filter(n -> n.name().toLowerCase().contains("client_secret")).findFirst().orElseThrow();
        assertEquals("HIGH", note.severity());
    }

    @Test
    public void keyMatchingIsCaseInsensitive() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("ACCESS_TOKEN", "value");

        assertTrue(hasNote(OAuthEngine.analyze("https://app.example/x", params), "token present in the url"));
    }

    @Test
    public void ordinaryRequestWithNoOAuthShapeProducesNoNotes() {
        Map<String, String> params = new LinkedHashMap<>();
        params.put("q", "search term");
        params.put("page", "2");

        assertTrue(OAuthEngine.analyze("https://app.example/search", params).isEmpty());
    }

    @Test
    public void emptyOrNullParamsProduceNoNotes() {
        assertTrue(OAuthEngine.analyze("https://app.example/x", Map.of()).isEmpty());
        assertTrue(OAuthEngine.analyze("https://app.example/x", null).isEmpty());
    }
}
