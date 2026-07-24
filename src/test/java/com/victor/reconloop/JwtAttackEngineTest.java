package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import static org.junit.Assert.*;

public class JwtAttackEngineTest {

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String decode(String segment) {
        int mod = segment.length() % 4;
        String padded = mod == 0 ? segment : segment + "====".substring(mod);
        return new String(Base64.getUrlDecoder().decode(padded), StandardCharsets.UTF_8);
    }

    private static String hs256Token(String secret) {
        String header = b64("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
        String payload = b64("{\"sub\":\"1234567890\",\"name\":\"test\"}");
        String signingInput = header + "." + payload;
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            String sig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
            return signingInput + "." + sig;
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Test
    public void headerAlgExtractsAndLowercasesTheAlgorithm() {
        String token = hs256Token("s3cret");
        assertEquals("hs256", JwtAttackEngine.headerAlg(token));
    }

    @Test
    public void headerAlgReturnsNullForMalformedToken() {
        assertNull(JwtAttackEngine.headerAlg("not-a-jwt"));
        assertNull(JwtAttackEngine.headerAlg(b64("{}")));
    }

    @Test
    public void forgeNoneVariantsProducesFourCaseVariantsWithEmptySignature() {
        String token = hs256Token("s3cret");
        String[] originalParts = token.split("\\.");

        List<String> variants = JwtAttackEngine.forgeNoneVariants(token);
        assertEquals(4, variants.size());

        Set<String> algsSeen = new java.util.HashSet<>();
        for (String variant : variants) {
            String[] parts = variant.split("\\.", -1);
            assertEquals(3, parts.length);
            assertEquals("", parts[2]);
            assertEquals("payload unchanged by the alg:none forgery", originalParts[1], parts[1]);

            String header = decode(parts[0]);
            java.util.regex.Matcher m = java.util.regex.Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]*)\"").matcher(header);
            assertTrue(m.find());
            algsSeen.add(m.group(1));
        }
        assertEquals(Set.of("none", "None", "NONE", "nOnE"), algsSeen);
    }

    @Test
    public void forgeNoneVariantsReturnsEmptyForTokenWithoutAlgClaim() {
        String token = b64("{\"typ\":\"JWT\"}") + ".payload.sig";
        assertTrue(JwtAttackEngine.forgeNoneVariants(token).isEmpty());
    }

    @Test
    public void forgeWithSecretProducesAVerifiableHmacSignatureAndInjectsMarkerClaim() throws Exception {
        String token = hs256Token("original-secret");
        String forged = JwtAttackEngine.forgeWithSecret(token, "cracked-secret", "hs256");
        assertNotNull(forged);

        String[] parts = forged.split("\\.");
        assertEquals(3, parts.length);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("cracked-secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        String expectedSig = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(mac.doFinal((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII)));
        assertEquals(expectedSig, parts[2]);

        String decodedPayload = decode(parts[1]);
        assertTrue(decodedPayload.contains("\"rh_forged\":1"));
        assertTrue(decodedPayload.contains("\"sub\":\"1234567890\""));
    }

    @Test
    public void forgeWithSecretSupportsAllThreeHmacAlgorithms() {
        String token = hs256Token("x");
        assertNotNull(JwtAttackEngine.forgeWithSecret(token, "k", "hs256"));
        assertNotNull(JwtAttackEngine.forgeWithSecret(token, "k", "hs384"));
        assertNotNull(JwtAttackEngine.forgeWithSecret(token, "k", "hs512"));
    }

    @Test
    public void forgeWithSecretRejectsNonHmacAlgorithms() {
        String token = hs256Token("x");
        assertNull(JwtAttackEngine.forgeWithSecret(token, "k", "rs256"));
        assertNull(JwtAttackEngine.forgeWithSecret(token, "k", null));
    }

    @Test
    public void forgeWithSecretRejectsMalformedTokenOrNonObjectPayload() {
        assertNull(JwtAttackEngine.forgeWithSecret("only-one-part", "k", "hs256"));
        String nonObjectPayload = b64("{\"alg\":\"HS256\"}") + "." + b64("\"just a string\"") + ".sig";
        assertNull(JwtAttackEngine.forgeWithSecret(nonObjectPayload, "k", "hs256"));
    }

    @Test
    public void extractJwtsFindsTokenInRawRequestText() {
        String token = hs256Token("s3cret");
        String raw = "GET /profile HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer " + token + "\r\n\r\n";

        HttpRequest fakeRequest = (HttpRequest) Proxy.newProxyInstance(
                HttpRequest.class.getClassLoader(),
                new Class<?>[]{HttpRequest.class},
                (proxy, method, args) -> "toString".equals(method.getName()) ? raw : null);

        Set<String> found = JwtAttackEngine.extractJwts(fakeRequest);
        assertTrue(found.contains(token));
    }

    @Test
    public void extractJwtsReturnsEmptySetForNullRequest() {
        assertTrue(JwtAttackEngine.extractJwts(null).isEmpty());
    }
}
