package com.victor.reconloop;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Passive web-hygiene analysis: CORS misconfiguration, Content-Security-Policy weaknesses, JSON Web
 * Token defects, session-cookie attribute hygiene, and a CSRF-protection heuristic. All inputs come
 * from observed traffic; nothing is sent.
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

        for (HttpHeader header : response.headers()) {
            if (header.name().equalsIgnoreCase("Set-Cookie")) analyzeCookie(header.value(), notes);
        }

        if (request != null) {
            List<String> headerNames = new ArrayList<>();
            for (HttpHeader header : request.headers()) headerNames.add(header.name());
            List<String> paramNames = new ArrayList<>();
            try {
                for (HttpParameter parameter : request.parameters()) paramNames.add(parameter.name());
            } catch (Exception ignored) {}
            analyzeCsrf(request.method(), request.headerValue("Cookie"), headerNames, paramNames, notes);
        }

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

    /** Cookie names that suggest session/authentication state, not general preferences. */
    private static final Set<String> SESSION_COOKIE_HINTS = Set.of(
            "session", "sess", "sid", "auth", "token", "jwt", "login", "remember", "csrftoken");

    private static final Set<String> STATE_CHANGING_METHODS = Set.of("POST", "PUT", "DELETE", "PATCH");

    private static final Set<String> CSRF_TOKEN_HINTS = Set.of(
            "csrf", "xsrf", "authenticitytoken", "requestverificationtoken");

    /** Parses one raw {@code Set-Cookie} header value and flags missing attributes on session-like cookies. */
    static void analyzeCookie(String setCookieValue, List<Note> notes) {
        if (setCookieValue == null || setCookieValue.isBlank()) return;
        String[] parts = setCookieValue.split(";");
        String nameValue = parts[0].trim();
        int eq = nameValue.indexOf('=');
        String name = (eq >= 0 ? nameValue.substring(0, eq) : nameValue).trim();
        if (name.isEmpty() || !looksLikeSessionCookie(name)) return;

        boolean secure = false, httpOnly = false;
        String sameSite = null;
        for (int i = 1; i < parts.length; i++) {
            String attr = parts[i].trim();
            String attrLower = attr.toLowerCase(Locale.ROOT);
            if (attrLower.equals("secure")) secure = true;
            else if (attrLower.equals("httponly")) httpOnly = true;
            else if (attrLower.startsWith("samesite")) {
                int eq2 = attr.indexOf('=');
                sameSite = eq2 >= 0 ? attr.substring(eq2 + 1).trim() : "";
            }
        }

        if (!httpOnly) {
            notes.add(new Note("MEDIUM", "Session cookie missing HttpOnly",
                    "Cookie \"" + name + "\" has no HttpOnly flag; a script-readable session cookie can be "
                            + "stolen via any XSS on the same origin."));
        }
        if (!secure) {
            notes.add(new Note("MEDIUM", "Session cookie missing Secure",
                    "Cookie \"" + name + "\" has no Secure flag; it can be sent over plain HTTP and intercepted "
                            + "on the network."));
        }
        if (sameSite == null || sameSite.isBlank()) {
            notes.add(new Note("LOW", "Session cookie missing SameSite",
                    "Cookie \"" + name + "\" sets no SameSite attribute; the browser default varies, so set "
                            + "SameSite=Strict or Lax explicitly to mitigate CSRF."));
        } else if (sameSite.equalsIgnoreCase("none")) {
            notes.add(new Note("LOW", "Session cookie uses SameSite=None",
                    "Cookie \"" + name + "\" explicitly disables same-site protection (SameSite=None)"
                            + (secure ? "." : ", and is also missing the Secure flag SameSite=None requires — modern browsers will reject this cookie entirely.")));
        }
    }

    private static boolean looksLikeSessionCookie(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        for (String hint : SESSION_COOKIE_HINTS) if (lower.contains(hint)) return true;
        return false;
    }

    /**
     * Flags a state-changing request that relies on a session-like cookie with no anti-CSRF
     * token/header evidence anywhere in the same request. A heuristic lead, not a confirmed bypass —
     * the app may enforce CSRF protection some other way this can't see (Origin/Referer checks, a
     * token name outside {@link #CSRF_TOKEN_HINTS}, etc.).
     */
    static void analyzeCsrf(String method, String cookieHeader, List<String> headerNames, List<String> paramNames, List<Note> notes) {
        if (method == null || !STATE_CHANGING_METHODS.contains(method.toUpperCase(Locale.ROOT))) return;
        if (cookieHeader == null || cookieHeader.isBlank() || !looksLikeSessionCookie(cookieHeader)) return;

        boolean hasCsrfHeader = headerNames != null && headerNames.stream().anyMatch(WebHygieneEngine::looksLikeCsrfName);
        boolean hasCsrfParam = paramNames != null && paramNames.stream().anyMatch(WebHygieneEngine::looksLikeCsrfName);
        if (hasCsrfHeader || hasCsrfParam) return;

        notes.add(new Note("LOW", "Possible missing CSRF protection",
                "A " + method.toUpperCase(Locale.ROOT) + " request carries a session-like cookie with no "
                        + "anti-CSRF token/header observed (no csrf/xsrf-named header or parameter). Verify "
                        + "SameSite cookie attributes and server-side CSRF-token validation for this endpoint."));
    }

    private static boolean looksLikeCsrfName(String name) {
        if (name == null) return false;
        String normalized = name.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
        for (String hint : CSRF_TOKEN_HINTS) if (normalized.contains(hint)) return true;
        return false;
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
