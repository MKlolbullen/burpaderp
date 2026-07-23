package com.victor.reconloop;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive web-hygiene analysis: CORS misconfiguration, Content-Security-Policy weaknesses, and
 * JSON Web Token defects. All inputs come from observed traffic; nothing is sent.
 *
 * <p>The analysis cores are pure static methods so they can be unit-tested without Burp.
 */
final class WebHygieneEngine {

    record Note(String severity, String name, String detail) {}

    private static final Pattern JWT =
            Pattern.compile("eyJ[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{5,}\\.[A-Za-z0-9_-]{0,}");

    List<Note> analyze(HttpRequest request, HttpResponse response) {
        List<Note> notes = new ArrayList<>();
        if (response == null) return notes;

        analyzeCors(request == null ? null : request.headerValue("Origin"),
                response.headerValue("Access-Control-Allow-Origin"),
                response.headerValue("Access-Control-Allow-Credentials"), notes);

        analyzeCsp(response.headerValue("Content-Security-Policy"),
                isHtml(response.headerValue("Content-Type")), notes);

        Set<String> seen = new HashSet<>();
        String haystack = (request == null ? "" : request.toString()) + "\n" + response.toString();
        Matcher matcher = JWT.matcher(haystack);
        while (matcher.find()) {
            String token = matcher.group();
            if (seen.add(token)) analyzeJwt(token, notes);
        }
        return notes;
    }

    // ---- pure cores ----

    static void analyzeCors(String origin, String acao, String acac, List<Note> notes) {
        if (acao == null || acao.isBlank()) return;
        boolean credentials = acac != null && acac.trim().equalsIgnoreCase("true");
        String value = acao.trim();

        if (value.equals("*")) {
            notes.add(new Note(credentials ? "MEDIUM" : "INFO", "CORS wildcard origin",
                    "Access-Control-Allow-Origin: * " + (credentials
                            ? "with Allow-Credentials:true (browsers block this combo, but it signals misconfiguration)."
                            : "(credentialed requests are not exposed).")));
        } else if (value.equalsIgnoreCase("null")) {
            notes.add(new Note(credentials ? "HIGH" : "MEDIUM", "CORS null origin allowed",
                    "Access-Control-Allow-Origin: null" + (credentials ? " with credentials — exploitable from sandboxed iframes." : ".")));
        } else if (origin != null && value.equalsIgnoreCase(origin.trim())) {
            notes.add(new Note(credentials ? "HIGH" : "MEDIUM", "CORS reflects request Origin",
                    "The response reflects the request Origin (" + origin + ")" + (credentials
                            ? " with Allow-Credentials:true — classic cross-origin data theft / account takeover surface."
                            : "; verify whether arbitrary origins are trusted.")));
        }
    }

    static void analyzeCsp(String csp, boolean htmlResponse, List<Note> notes) {
        if (csp == null || csp.isBlank()) {
            if (htmlResponse) notes.add(new Note("LOW", "Missing Content-Security-Policy",
                    "HTML response served without a Content-Security-Policy header."));
            return;
        }
        String lower = csp.toLowerCase(Locale.ROOT);
        if (lower.contains("'unsafe-inline'"))
            notes.add(new Note("MEDIUM", "CSP allows 'unsafe-inline'",
                    "'unsafe-inline' in the policy largely defeats CSP's XSS protection."));
        if (lower.contains("'unsafe-eval'"))
            notes.add(new Note("LOW", "CSP allows 'unsafe-eval'",
                    "'unsafe-eval' permits eval()/Function() and weakens the policy."));
        if (containsSourceWildcard(lower, "script-src") || containsSourceWildcard(lower, "default-src"))
            notes.add(new Note("MEDIUM", "CSP script source wildcard",
                    "A wildcard (*) script/default source allows scripts from any host."));
        if (!lower.contains("object-src"))
            notes.add(new Note("LOW", "CSP missing object-src",
                    "No object-src directive; consider object-src 'none' to block plugin-based vectors."));
        if (!lower.contains("base-uri"))
            notes.add(new Note("LOW", "CSP missing base-uri",
                    "No base-uri directive; <base> injection can redirect relative script loads."));
    }

    static void analyzeJwt(String token, List<Note> notes) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) return;
        String header = decodeSegment(parts[0]);
        if (header == null) return;

        String alg = extractJsonString(header, "alg");
        if (alg == null) return;
        String algLower = alg.toLowerCase(Locale.ROOT);

        if (algLower.equals("none")) {
            notes.add(new Note("HIGH", "JWT alg:none",
                    "A token advertises alg:none; if the server accepts it, signatures can be stripped."));
        } else if (algLower.startsWith("hs")) {
            notes.add(new Note("LOW", "JWT HMAC algorithm (" + alg + ")",
                    "Symmetric HMAC token — vulnerable to offline secret cracking if a weak key is used."));
            if (parts.length >= 3) {
                String secret = crackHmac(parts[0] + "." + parts[1], parts[2], algLower);
                if (secret != null) {
                    notes.add(new Note("HIGH", "JWT signed with a weak/known secret",
                            "The token's HMAC signature verifies with the well-known secret \"" + secret + "\". "
                            + "Anyone with this secret can forge arbitrary tokens — full authentication bypass / "
                            + "privilege escalation. Rotate to a long random key immediately."));
                }
            }
        } else {
            notes.add(new Note("INFO", "JWT observed (" + alg + ")",
                    "JSON Web Token present in traffic; review claims and validation."));
        }
        if (header.toLowerCase(Locale.ROOT).contains("\"kid\""))
            notes.add(new Note("INFO", "JWT kid header present",
                    "A 'kid' header can be an injection point (path traversal / SQLi) into key resolution."));
    }

    /** A small dictionary of secrets that ship in tutorials/boilerplate and get left in production. */
    private static final List<String> WEAK_SECRETS = List.of(
            "secret", "password", "123456", "changeme", "admin", "jwt", "token", "key", "test", "private",
            "secretkey", "supersecret", "your-256-bit-secret", "your_jwt_secret", "jwtsecret", "mysecret",
            "s3cr3t", "p@ssw0rd", "qwerty", "letmein", "default", "root", "password123", "1234567890",
            "hmac", "signature", "access", "refresh", "api", "dev", "staging", "production", "shhhh");

    /** Offline HS256/384/512 secret check: returns the matching weak secret, or null. No traffic is sent. */
    static String crackHmac(String signingInput, String signature, String algLower) {
        String macAlg = switch (algLower) {
            case "hs256" -> "HmacSHA256";
            case "hs384" -> "HmacSHA384";
            case "hs512" -> "HmacSHA512";
            default -> null;
        };
        if (macAlg == null || signature == null || signature.isBlank()) return null;
        for (String secret : WEAK_SECRETS) {
            try {
                Mac mac = Mac.getInstance(macAlg);
                mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), macAlg));
                byte[] computed = mac.doFinal(signingInput.getBytes(StandardCharsets.US_ASCII));
                String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(computed);
                if (encoded.equals(signature)) return secret;
            } catch (Exception ignored) {
                // unavailable MAC algorithm -> skip
            }
        }
        return null;
    }

    private static boolean containsSourceWildcard(String csp, String directive) {
        int at = csp.indexOf(directive);
        if (at < 0) return false;
        int end = csp.indexOf(';', at);
        String segment = csp.substring(at, end < 0 ? csp.length() : end);
        return segment.contains(" *") || segment.contains(" http://*") || segment.contains(" https://*");
    }

    private static boolean isHtml(String contentType) {
        return contentType != null && contentType.toLowerCase(Locale.ROOT).contains("html");
    }

    private static String decodeSegment(String segment) {
        try {
            return new String(Base64.getUrlDecoder().decode(padBase64(segment)));
        } catch (Exception e) {
            return null;
        }
    }

    private static String padBase64(String value) {
        int mod = value.length() % 4;
        return mod == 0 ? value : value + "====".substring(mod);
    }

    private static String extractJsonString(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return matcher.find() ? matcher.group(1) : null;
    }
}
