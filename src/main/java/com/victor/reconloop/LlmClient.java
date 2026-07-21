package com.victor.reconloop;

import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Minimal, dependency-free client that sends a single-shot prompt to a configured {@link LlmProvider}
 * and returns the assistant's text. Calls go direct (respecting any system proxy) rather than through
 * Burp, so API keys never appear in the proxy history or trip the extension's own secret scanner.
 *
 * <p>Response parsing is a targeted JSON string read for the provider's answer field — good enough for
 * a single completion without pulling in a JSON dependency, and it degrades to a readable error string
 * on non-200 responses.
 */
final class LlmClient {

    static final String DEFAULT_JS_SYSTEM_PROMPT =
            "You are a senior application-security reviewer assisting an authorised bug-bounty tester. "
            + "Analyse the provided client-side code or HTTP content. Identify: API endpoints and their "
            + "parameters, authentication/authorization logic, hardcoded secrets or tokens, dangerous DOM "
            + "sinks and their sources (potential DOM XSS), interesting or hidden functionality, and any "
            + "notable attack surface. Be concise and specific; cite the relevant code. Do not fabricate.";

    static final String REQUEST_ANALYSIS_SYSTEM_PROMPT =
            "You are a senior web-application penetration tester reviewing a single HTTP request/response "
            + "for an authorised engagement. Explain what the endpoint does, then enumerate its attack "
            + "surface: every parameter/header/cookie an attacker controls, the injection or logic classes "
            + "each could enable (IDOR/BOLA, SQLi, SSRF, SSTI, XSS, open redirect, auth/session flaws, mass "
            + "assignment), and what to change in the request to test each. Be specific and cite the exact "
            + "field. Do not fabricate findings; mark anything speculative as such.";

    static final String CHAIN_SYSTEM_PROMPT =
            "You are a senior offensive-security engineer assisting an AUTHORISED bug-bounty tester. From the "
            + "provided HTTP request/response or code, identify concrete vulnerabilities, then focus on how to "
            + "CHAIN them into higher-impact attacks. For each realistic chain, give: (1) the primitives it "
            + "combines and where each is observed here, (2) an ordered, reproducible sequence of steps with "
            + "the exact request modifications/payloads, (3) the resulting impact (e.g. account takeover, data "
            + "exfiltration, RCE), and (4) how to confirm it safely. Prefer chains supported by evidence in the "
            + "input; clearly separate confirmed primitives from assumptions. Consider classic chains such as "
            + "open-redirect -> OAuth code/token theft, SSRF -> cloud metadata -> credential use, reflected "
            + "input + weak CSP -> XSS -> session/CSRF-token theft, IDOR + predictable IDs from source maps or "
            + "API specs -> mass data access, host-header injection -> password-reset poisoning, and exposed "
            + "secrets -> authenticated API abuse. Only target systems the tester is authorised to test; do not "
            + "invent evidence.";

    private static final int MAX_OUTPUT_TOKENS = 4096;
    private static final int MAX_INPUT_CHARS = 200_000;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .proxy(ProxySelector.getDefault())
            .build();

    String complete(LlmProvider provider, String model, String apiKey, String system, String prompt) {
        if (provider == null) return "[error] No provider selected.";
        if (apiKey == null || apiKey.isBlank()) {
            return "[error] No API key. Set it in the field or export $" + provider.envVar() + ".";
        }
        String usedModel = model == null || model.isBlank() ? provider.defaultModel() : model.trim();
        String input = prompt == null ? "" : prompt;
        if (input.length() > MAX_INPUT_CHARS) input = input.substring(0, MAX_INPUT_CHARS);

        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(provider.endpoint(usedModel, apiKey)))
                    .timeout(Duration.ofSeconds(120))
                    .POST(HttpRequest.BodyPublishers.ofString(
                            provider.requestBody(usedModel, system, input, MAX_OUTPUT_TOKENS)));
            for (String[] header : provider.headers(apiKey)) {
                builder.header(header[0], header[1]);
            }

            HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            String body = response.body();
            if (response.statusCode() != 200) {
                return "[HTTP " + response.statusCode() + "] " + snippet(body);
            }
            String text = extractString(body, provider.responseField());
            return text != null ? text : "[warning] Could not parse response:\n" + snippet(body);
        } catch (Exception e) {
            return "[error] Request failed: " + e.getMessage();
        }
    }

    /** Reads the first JSON string value for {@code "field"}, honouring escapes. */
    static String extractString(String json, String field) {
        if (json == null) return null;
        String needle = "\"" + field + "\"";
        int at = json.indexOf(needle);
        while (at >= 0) {
            int i = at + needle.length();
            while (i < json.length() && (json.charAt(i) == ' ' || json.charAt(i) == ':')) i++;
            if (i < json.length() && json.charAt(i) == '"') {
                return readJsonString(json, i);
            }
            at = json.indexOf(needle, at + needle.length());
        }
        return null;
    }

    private static String readJsonString(String json, int openQuote) {
        StringBuilder out = new StringBuilder();
        int i = openQuote + 1;
        while (i < json.length()) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char n = json.charAt(i + 1);
                switch (n) {
                    case 'n' -> out.append('\n');
                    case 'r' -> out.append('\r');
                    case 't' -> out.append('\t');
                    case 'b' -> out.append('\b');
                    case 'f' -> out.append('\f');
                    case 'u' -> {
                        if (i + 5 < json.length()) {
                            try {
                                out.append((char) Integer.parseInt(json.substring(i + 2, i + 6), 16));
                                i += 4;
                            } catch (NumberFormatException ignored) { out.append(n); }
                        }
                    }
                    default -> out.append(n); // \" \\ \/
                }
                i += 2;
            } else if (c == '"') {
                return out.toString();
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }

    private static String snippet(String body) {
        if (body == null) return "(empty)";
        String trimmed = body.strip();
        return trimmed.length() <= 600 ? trimmed : trimmed.substring(0, 597) + "...";
    }
}
