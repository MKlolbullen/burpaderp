package com.victor.reconloop;

import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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

    /**
     * Structured JS review prompt: the model must return machine-parseable JSON
     * so each finding can be filed as a native Burp audit issue (with a PoC and,
     * where applicable, an exploit chain) rather than free-form text.
     */
    static final String JS_FINDINGS_SYSTEM_PROMPT =
            "You are a senior application-security reviewer assisting an AUTHORISED bug-bounty tester. "
            + "Analyse the provided JavaScript / client-side source for security vulnerabilities and, where "
            + "possible, how they could be chained into higher-impact attacks.\n\n"
            + "Return STRICT JSON ONLY — no prose, no markdown, no code fences. Use exactly this schema:\n"
            + "{\"findings\":[{"
            + "\"title\":\"short specific finding name\","
            + "\"severity\":\"HIGH|MEDIUM|LOW|INFO\","
            + "\"confidence\":\"CERTAIN|FIRM|TENTATIVE\","
            + "\"vuln_class\":\"e.g. DOM XSS, hardcoded secret, SSRF, open redirect, prototype pollution, insecure postMessage, IDOR, CORS misconfig\","
            + "\"description\":\"what the bug is and why it is exploitable, citing the specific function/sink/source in the code\","
            + "\"evidence\":\"the exact code snippet or symbol that demonstrates it\","
            + "\"poc\":\"a concrete reproducible proof-of-concept: the URL, request, or DOM interaction that triggers it, with the payload\","
            + "\"chain\":\"if this primitive can be combined with other issues for higher impact (account takeover, RCE, data exfiltration), give the ordered chain; otherwise an empty string\","
            + "\"remediation\":\"how to fix it\""
            + "}]}\n\n"
            + "Only report issues you can justify from the code; mark uncertain ones TENTATIVE. If there are no "
            + "issues, return {\"findings\":[]}. Do not fabricate evidence. Never suggest testing systems the "
            + "tester is not authorised to assess.";

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

    /** A single structured vulnerability finding returned by the LLM. */
    record LlmFinding(String title, String severity, String confidence, String vulnClass,
                      String description, String evidence, String poc, String chain, String remediation) {}

    /** Result of a structured analysis: parsed findings plus an optional error/raw fallback message. */
    record LlmAnalysis(List<LlmFinding> findings, String error) {}

    /**
     * Sends one JavaScript resource to the LLM for structured vulnerability review and parses the
     * JSON findings. On a transport/HTTP error, or when the reply cannot be parsed as findings, the
     * returned {@link LlmAnalysis} carries an {@code error} message and an empty findings list.
     */
    LlmAnalysis analyzeJavaScript(LlmProvider provider, String model, String apiKey, String sourceUrl, String source) {
        String input = "// Source URL: " + (sourceUrl == null ? "(unknown)" : sourceUrl) + "\n"
                + (source == null ? "" : source);
        String raw = complete(provider, model, apiKey, JS_FINDINGS_SYSTEM_PROMPT, input);
        if (raw == null || raw.startsWith("[error]") || raw.startsWith("[HTTP") || raw.startsWith("[warning]")) {
            return new LlmAnalysis(List.of(), raw == null ? "[error] no response" : raw);
        }
        List<LlmFinding> findings = parseFindings(raw);
        return new LlmAnalysis(findings, findings.isEmpty() ? "[no findings parsed] " + snippet(raw) : null);
    }

    /** Extracts findings from the model's reply, tolerating code fences and surrounding prose. */
    static List<LlmFinding> parseFindings(String raw) {
        List<LlmFinding> out = new ArrayList<>();
        String json = isolateJson(raw);
        if (json == null) return out;
        try {
            Object root = Json.parse(json);
            Map<String, Object> obj = Json.asObject(root);
            List<Object> arr = obj != null ? Json.asArray(obj.get("findings")) : Json.asArray(root);
            if (arr == null) return out;
            for (Object item : arr) {
                Map<String, Object> f = Json.asObject(item);
                if (f == null) continue;
                out.add(new LlmFinding(
                        nz(Json.str(f, "title"), "Untitled finding"),
                        nz(Json.str(f, "severity"), "INFO"),
                        nz(Json.str(f, "confidence"), "TENTATIVE"),
                        nz(Json.str(f, "vuln_class"), ""),
                        nz(Json.str(f, "description"), ""),
                        nz(Json.str(f, "evidence"), ""),
                        nz(Json.str(f, "poc"), ""),
                        nz(Json.str(f, "chain"), ""),
                        nz(Json.str(f, "remediation"), "")));
            }
        } catch (Exception ignored) {
            // malformed JSON -> caller falls back to the raw error message
        }
        return out;
    }

    /** Strips markdown fences and returns the outermost JSON object/array substring, or null. */
    static String isolateJson(String raw) {
        if (raw == null) return null;
        String t = raw.strip();
        if (t.startsWith("```")) {
            int nl = t.indexOf('\n');
            if (nl >= 0) t = t.substring(nl + 1);
            int fence = t.lastIndexOf("```");
            if (fence >= 0) t = t.substring(0, fence);
            t = t.strip();
        }
        int start = t.indexOf('{');
        int arrStart = t.indexOf('[');
        if (start < 0 || (arrStart >= 0 && arrStart < start)) start = arrStart;
        if (start < 0) return null;
        int endObj = t.lastIndexOf('}');
        int endArr = t.lastIndexOf(']');
        int end = Math.max(endObj, endArr);
        if (end < start) return null;
        return t.substring(start, end + 1);
    }

    private static String nz(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
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
