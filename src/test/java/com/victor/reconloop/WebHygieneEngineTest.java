package com.victor.reconloop;

import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.*;

public class WebHygieneEngineTest {

    private static boolean hasNote(List<WebHygieneEngine.Note> notes, String nameContains) {
        return notes.stream().anyMatch(n -> n.name().toLowerCase().contains(nameContains.toLowerCase()));
    }

    // ---- CORS ----

    @Test
    public void corsWildcardWithoutCredentialsIsInfo() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCors("https://evil.example", "*", null, notes);
        assertEquals(1, notes.size());
        assertEquals("INFO", notes.get(0).severity());
    }

    @Test
    public void corsWildcardWithCredentialsIsMedium() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCors("https://evil.example", "*", "true", notes);
        assertEquals("MEDIUM", notes.get(0).severity());
    }

    @Test
    public void corsNullOriginWithCredentialsIsHigh() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCors(null, "null", "true", notes);
        assertEquals("HIGH", notes.get(0).severity());
        assertTrue(hasNote(notes, "null origin"));
    }

    @Test
    public void corsReflectingRequestOriginWithCredentialsIsHigh() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCors("https://evil.example", "https://evil.example", "true", notes);
        assertEquals("HIGH", notes.get(0).severity());
        assertTrue(hasNote(notes, "reflects request origin"));
    }

    @Test
    public void corsFixedTrustedOriginIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCors("https://attacker.example", "https://trusted.example", null, notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void blankAcaoProducesNoNotes() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCors("https://a.example", null, null, notes);
        assertTrue(notes.isEmpty());
    }

    // ---- CSP ----

    @Test
    public void missingCspOnHtmlIsFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsp(null, true, notes);
        assertEquals(1, notes.size());
        assertTrue(hasNote(notes, "missing content-security-policy"));
    }

    @Test
    public void missingCspOnNonHtmlIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsp(null, false, notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void weakCspDirectivesAreEachFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsp("default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval' *", true, notes);
        assertTrue(hasNote(notes, "unsafe-inline"));
        assertTrue(hasNote(notes, "unsafe-eval"));
        assertTrue(hasNote(notes, "wildcard"));
        assertTrue(hasNote(notes, "missing object-src"));
        assertTrue(hasNote(notes, "missing base-uri"));
    }

    @Test
    public void strongCspProducesNoNotes() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsp("default-src 'self'; object-src 'none'; base-uri 'self'", true, notes);
        assertTrue(notes.isEmpty());
    }

    // ---- Cookie hygiene ----

    @Test
    public void nonSessionCookieIsIgnoredRegardlessOfFlags() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCookie("theme=dark", notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void sessionCookieWithNoFlagsIsFlaggedForAllThree() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCookie("session_id=abc123; Path=/", notes);
        assertTrue(hasNote(notes, "missing httponly"));
        assertTrue(hasNote(notes, "missing secure"));
        assertTrue(hasNote(notes, "missing samesite"));
        assertEquals(3, notes.size());
    }

    @Test
    public void sessionCookieWithAllProtectionsIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCookie("session_id=abc123; Path=/; HttpOnly; Secure; SameSite=Strict", notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void sessionCookieWithSameSiteNoneAndSecureFlagsOnlyTheSameSiteChoice() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCookie("authtoken=abc; HttpOnly; Secure; SameSite=None", notes);
        assertEquals(1, notes.size());
        assertTrue(hasNote(notes, "samesite=none"));
        assertFalse(hasNote(notes, "missing secure"));
        assertFalse(hasNote(notes, "missing httponly"));
    }

    @Test
    public void blankOrNullCookieValueIsSafe() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCookie(null, notes);
        WebHygieneEngine.analyzeCookie("", notes);
        assertTrue(notes.isEmpty());
    }

    // ---- CSRF heuristic ----

    @Test
    public void getRequestsAreNeverFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("GET", "session_id=abc", List.of(), List.of(), notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void postWithoutCookieIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("POST", null, List.of(), List.of(), notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void postWithNonSessionCookieIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("POST", "theme=dark", List.of(), List.of(), notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void postWithSessionCookieAndNoTokenIsFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("POST", "session_id=abc", List.of("Content-Type"), List.of("amount", "to"), notes);
        assertEquals(1, notes.size());
        assertTrue(hasNote(notes, "csrf"));
    }

    @Test
    public void postWithCsrfHeaderIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("POST", "session_id=abc", List.of("X-CSRF-Token"), List.of(), notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void postWithCsrfBodyParamIsNotFlagged() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("POST", "session_id=abc", List.of(), List.of("csrf_token"), notes);
        assertTrue(notes.isEmpty());
    }

    @Test
    public void putAndDeleteAndPatchAreAlsoCheckedLikePost() {
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeCsrf("PUT", "session_id=abc", List.of(), List.of(), notes);
        WebHygieneEngine.analyzeCsrf("DELETE", "session_id=abc", List.of(), List.of(), notes);
        WebHygieneEngine.analyzeCsrf("PATCH", "session_id=abc", List.of(), List.of(), notes);
        assertEquals(3, notes.size());
    }

    // ---- JWT ----

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String hs256Token(String secret) {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = b64("{\"sub\":\"1\"}");
        String signingInput = header + "." + payload;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
            return signingInput + "." + sig;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    public void algNoneIsFlaggedHigh() {
        String token = b64("{\"alg\":\"none\"}") + "." + b64("{\"sub\":\"1\"}") + ".";
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeJwt(token, notes);
        assertTrue(notes.stream().anyMatch(n -> n.severity().equals("HIGH") && n.name().toLowerCase().contains("alg:none")));
    }

    @Test
    public void hs256WithWeakSecretIsCracked() {
        String token = hs256Token("secret");
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeJwt(token, notes);
        assertTrue(hasNote(notes, "hmac algorithm"));
        assertTrue(hasNote(notes, "weak/known secret"));
    }

    @Test
    public void hs256WithStrongSecretIsNotCracked() {
        String token = hs256Token("a-sufficiently-long-random-secret-value-12345");
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeJwt(token, notes);
        assertTrue(hasNote(notes, "hmac algorithm"));
        assertFalse(hasNote(notes, "weak/known secret"));
    }

    @Test
    public void kidHeaderPresenceIsNoted() {
        String token = b64("{\"alg\":\"RS256\",\"kid\":\"key-1\"}") + "." + b64("{\"sub\":\"1\"}") + ".sig";
        List<WebHygieneEngine.Note> notes = new ArrayList<>();
        WebHygieneEngine.analyzeJwt(token, notes);
        assertTrue(hasNote(notes, "kid header"));
    }

    @Test
    public void crackHmacReturnsNullForNonHmacAlgOrBlankSignature() {
        assertNull(WebHygieneEngine.crackHmac("x", "sig", "rs256"));
        assertNull(WebHygieneEngine.crackHmac("x", "", "hs256"));
        assertNull(WebHygieneEngine.crackHmac("x", null, "hs256"));
    }
}
