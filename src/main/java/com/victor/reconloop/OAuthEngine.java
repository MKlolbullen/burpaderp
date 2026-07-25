package com.victor.reconloop;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Passive OAuth 2.0 / OIDC authorization-flow heuristics. Works purely from a request's URL and its
 * query parameters — this observes traffic, it never drives an OAuth flow itself. Pure and
 * dependency-free so it's directly unit-testable.
 */
final class OAuthEngine {

    record Note(String severity, String name, String detail) {}

    /**
     * Analyzes one request's URL-level parameters (never body parameters — every check here is
     * specifically about what's visible in the URL: query strings get logged by servers/proxies and
     * leak via the Referer header and browser history, which is exactly what a legitimate
     * server-to-server token-endpoint POST body avoids).
     */
    static List<Note> analyze(String url, Map<String, String> urlParams) {
        List<Note> notes = new ArrayList<>();
        if (urlParams == null || urlParams.isEmpty()) return notes;
        Map<String, String> params = lowerKeys(urlParams);

        boolean looksLikeAuthRequest = params.containsKey("response_type") && params.containsKey("client_id");
        if (looksLikeAuthRequest) {
            analyzeAuthorizationRequest(params, notes);
        }
        checkTokenExposure(params, notes);
        return notes;
    }

    private static void analyzeAuthorizationRequest(Map<String, String> params, List<Note> notes) {
        String responseType = nz(params.get("response_type")).toLowerCase(Locale.ROOT);
        boolean hasState = !isBlank(params.get("state"));
        boolean hasPkce = !isBlank(params.get("code_challenge"));
        boolean implicit = responseType.contains("token"); // covers "token" and "id_token" (and hybrid variants)

        if (implicit) {
            notes.add(new Note("LOW", "OAuth implicit/hybrid flow in use",
                    "response_type=" + responseType + " returns a token directly in the redirect (typically the URL "
                            + "fragment), exposing it to browser history, extensions, and any script on the "
                            + "redirect page. Prefer the authorization-code flow with PKCE instead."));
        }
        if (!hasState) {
            notes.add(new Note("MEDIUM", "OAuth authorization request missing state",
                    "No (or an empty) 'state' parameter was sent. Without it, the authorization response can't be "
                            + "bound to the request that initiated it, enabling CSRF against the OAuth callback "
                            + "(login CSRF / account-linking CSRF)."));
        }
        if (!implicit && !hasPkce) {
            notes.add(new Note("LOW", "OAuth authorization-code request missing PKCE",
                    "No 'code_challenge' parameter was sent. PKCE (RFC 7636) protects the authorization code from "
                            + "interception/replay and is recommended for every client type, not only public ones."));
        }
    }

    private static void checkTokenExposure(Map<String, String> params, List<Note> notes) {
        for (String key : List.of("access_token", "id_token", "refresh_token")) {
            if (!isBlank(params.get(key))) {
                notes.add(new Note("MEDIUM", "OAuth/OIDC token present in the URL",
                        "'" + key + "' was sent as a URL parameter, which gets logged by servers/proxies and leaks "
                                + "via the Referer header and browser history. Tokens should only travel in the "
                                + "request body or an Authorization header."));
            }
        }
        if (!isBlank(params.get("client_secret"))) {
            notes.add(new Note("HIGH", "OAuth client_secret exposed in a URL",
                    "A 'client_secret' value was observed in URL parameters. A confidential client secret must "
                            + "never be reachable from the browser/URL — treat it as compromised and rotate it."));
        }
    }

    private static boolean isBlank(String s) { return s == null || s.isBlank(); }

    private static String nz(String s) { return s == null ? "" : s; }

    private static Map<String, String> lowerKeys(Map<String, String> params) {
        Map<String, String> out = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            out.put(entry.getKey().toLowerCase(Locale.ROOT), entry.getValue());
        }
        return out;
    }
}
