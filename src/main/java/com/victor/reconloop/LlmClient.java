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

    /** A configured, ready-to-use provider + model + resolved API key (UI field or $ENV already applied). */
    record LlmCredential(LlmProvider provider, String model, String apiKey) {}

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

    /**
     * Nuclei template author prompt. The reply must be a single valid Nuclei (v3) YAML template and
     * nothing else, so it can be saved straight to disk and run with {@code nuclei -t}. This mirrors
     * ProjectDiscovery's cloud {@code POST /v1/template/ai} capability but works with any configured
     * LLM provider and no PDCP account.
     */
    static final String NUCLEI_TEMPLATE_SYSTEM_PROMPT =
            "You are an expert detection engineer who writes Nuclei templates for ProjectDiscovery's scanner. "
            + "Given a description of a vulnerability, misconfiguration or check, output ONE complete, valid "
            + "Nuclei v3 YAML template and NOTHING else — no prose, no explanation, no markdown code fences.\n\n"
            + "Requirements:\n"
            + "- Top-level `id` (lowercase, hyphenated, unique-ish).\n"
            + "- `info:` with `name`, `author: recon-hound`, `severity` (info|low|medium|high|critical), a concise "
            + "`description`, `reference` (if applicable) and relevant `tags`.\n"
            + "- An `http:` block (or `dns:`/`ssl:`/`file:`/`headless:`/`code:` if more appropriate) using Nuclei "
            + "primitives: `{{BaseURL}}`, `{{Hostname}}`, path lists, `matchers` (word/regex/status/dsl), "
            + "`matchers-condition`, and `extractors` where useful. Prefer precise matchers to minimise false positives.\n"
            + "- Use interactsh (`{{interactsh-url}}` + an `interactsh_protocol`/`interactsh_request` matcher) for "
            + "blind/OOB checks such as SSRF or blind injection.\n"
            + "- Keep it safe and non-destructive; do not include payloads that damage the target.\n"
            + "Output only the YAML document.";

    /**
     * Cross-finding chaining prompt: operates over the WHOLE inventory of findings (not one message)
     * and returns ranked, reproducible exploit chains as strict JSON, each with a bug-bounty-ready
     * writeup, so every chain can be filed as its own native Burp issue.
     */
    static final String CHAIN_INVENTORY_SYSTEM_PROMPT =
            "You are a senior offensive-security engineer assisting an AUTHORISED bug-bounty tester. You are "
            + "given an INVENTORY of individual findings discovered on one target. Your job is to identify how "
            + "these primitives can be COMBINED into higher-impact exploit chains (account takeover, RCE, data "
            + "exfiltration, privilege escalation) that are worth more than the sum of the parts.\n\n"
            + "Return STRICT JSON ONLY — no prose, no markdown, no code fences. Schema:\n"
            + "{\"chains\":[{"
            + "\"title\":\"short name for the chain\","
            + "\"severity\":\"HIGH|MEDIUM|LOW|INFO\","
            + "\"confidence\":\"CERTAIN|FIRM|TENTATIVE\","
            + "\"primitives\":[\"which inventory findings it combines, each referencing the finding and its URL\"],"
            + "\"steps\":[\"ordered, reproducible steps with the exact requests/payloads\"],"
            + "\"impact\":\"the concrete end impact\","
            + "\"writeup\":\"a concise bug-bounty-ready narrative a triager can follow\","
            + "\"involved_urls\":[\"the URLs/endpoints involved\"]"
            + "}]}\n\n"
            + "Rank chains by impact (most severe first). Only propose chains supported by the inventory; clearly "
            + "keep speculative links TENTATIVE. If nothing chains, return {\"chains\":[]}. Do not fabricate "
            + "findings or evidence, and never suggest testing systems the tester is not authorised to assess.";

    /**
     * False-positive triage prompt: reviews a numbered batch of already-filed findings and judges
     * each on its own merits, purely from the evidence given — it must not assume prior findings in
     * the batch are correct just because they were flagged by a heuristic.
     */
    static final String TRIAGE_SYSTEM_PROMPT =
            "You are a senior application-security triager reviewing a batch of findings raised by an "
            + "automated scanner (regex/heuristic secret detection, response-disclosure signals, header "
            + "hygiene checks, endpoint-exposure detection, etc.) for an AUTHORISED security assessment. "
            + "Heuristic scanners over-report: judge each finding independently on the evidence given, not "
            + "on the fact that a rule fired.\n\n"
            + "For each numbered finding, decide whether it is a real, actionable issue or a false/noise "
            + "positive (a placeholder value, a non-sensitive default, a benign coincidental pattern match, "
            + "informational noise with no real risk, etc.).\n\n"
            + "Return STRICT JSON ONLY — no prose, no markdown, no code fences. Use exactly this schema:\n"
            + "{\"verdicts\":[{"
            + "\"index\":1,"
            + "\"verdict\":\"LIKELY_TP|UNCERTAIN|LIKELY_FP\","
            + "\"reasoning\":\"one concise sentence citing the specific evidence\""
            + "}]}\n\n"
            + "Include exactly one entry per finding number given, in any order. LIKELY_TP means a real "
            + "practitioner should act on it; LIKELY_FP means it is very unlikely to be a genuine issue; "
            + "UNCERTAIN means the evidence given isn't enough to tell either way. Do not fabricate reasoning "
            + "not supported by the given evidence.";

    /** One finding's ensemble-independent verdict from a single LLM call. */
    record TriageVerdict(int index, String verdict, String reasoning) {}

    /** Result of triaging one batch with one provider. */
    record TriageBatchResult(List<TriageVerdict> verdicts, String error) {}

    /**
     * Sends a numbered batch-of-findings prompt to one provider and parses its per-finding verdicts.
     * Callers fan this out across every enabled credential themselves for ensemble/majority-vote triage.
     */
    TriageBatchResult triage(LlmCredential credential, String batchPrompt) {
        String raw = complete(credential.provider(), credential.model(), credential.apiKey(), TRIAGE_SYSTEM_PROMPT, batchPrompt);
        if (raw == null || raw.startsWith("[error]") || raw.startsWith("[HTTP") || raw.startsWith("[warning]")) {
            return new TriageBatchResult(List.of(), raw == null ? "[error] no response" : raw);
        }
        List<TriageVerdict> verdicts = parseTriageVerdicts(raw);
        return new TriageBatchResult(verdicts, verdicts.isEmpty() ? "[no verdicts parsed] " + snippet(raw) : null);
    }

    static List<TriageVerdict> parseTriageVerdicts(String raw) {
        List<TriageVerdict> out = new ArrayList<>();
        String json = isolateJson(raw);
        if (json == null) return out;
        try {
            Object root = Json.parse(json);
            Map<String, Object> obj = Json.asObject(root);
            List<Object> arr = obj != null ? Json.asArray(obj.get("verdicts")) : Json.asArray(root);
            if (arr == null) return out;
            for (Object item : arr) {
                Map<String, Object> v = Json.asObject(item);
                if (v == null) continue;
                Object idxRaw = v.get("index");
                int index = idxRaw instanceof Number n ? n.intValue() : -1;
                if (index < 0) continue;
                out.add(new TriageVerdict(index, nz(Json.str(v, "verdict"), "UNCERTAIN"), nz(Json.str(v, "reasoning"), "")));
            }
        } catch (Exception ignored) {
            // malformed JSON -> caller falls back to the raw error message
        }
        return out;
    }

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

    /**
     * Generates a Nuclei YAML template from a natural-language description using the configured LLM.
     * Returns the raw template text, or a {@code [error]/[HTTP]} string on failure.
     */
    String generateNucleiTemplate(LlmProvider provider, String model, String apiKey, String description) {
        String raw = complete(provider, model, apiKey, NUCLEI_TEMPLATE_SYSTEM_PROMPT,
                description == null ? "" : description);
        if (raw == null || raw.startsWith("[error]") || raw.startsWith("[HTTP") || raw.startsWith("[warning]")) {
            return raw == null ? "[error] no response" : raw;
        }
        return stripCodeFences(raw);
    }

    /** Removes a leading ```lang fence and trailing ``` so the reply is a clean document. */
    static String stripCodeFences(String raw) {
        if (raw == null) return "";
        String t = raw.strip();
        if (t.startsWith("```")) {
            int nl = t.indexOf('\n');
            if (nl >= 0) t = t.substring(nl + 1);
            int fence = t.lastIndexOf("```");
            if (fence >= 0) t = t.substring(0, fence);
            t = t.strip();
        }
        return t;
    }

    /** A single structured vulnerability finding returned by the LLM. */
    record LlmFinding(String title, String severity, String confidence, String vulnClass,
                      String description, String evidence, String poc, String chain, String remediation) {}

    /** Result of a structured analysis: parsed findings plus an optional error/raw fallback message. */
    record LlmAnalysis(List<LlmFinding> findings, String error) {}

    /** A ranked exploit chain combining several primitives into higher impact. */
    record LlmChain(String title, String severity, String confidence, String primitives,
                    String steps, String impact, String writeup, String involvedUrls) {}

    /** Result of a chaining analysis over the finding inventory. */
    record ChainAnalysis(List<LlmChain> chains, String error) {}

    /**
     * Sends an inventory of findings to the LLM and parses the ranked exploit chains it proposes.
     * On transport/HTTP error or unparseable output, returns an empty list with an {@code error}.
     */
    ChainAnalysis analyzeChains(LlmProvider provider, String model, String apiKey, String inventory) {
        String raw = complete(provider, model, apiKey, CHAIN_INVENTORY_SYSTEM_PROMPT, inventory);
        if (raw == null || raw.startsWith("[error]") || raw.startsWith("[HTTP") || raw.startsWith("[warning]")) {
            return new ChainAnalysis(List.of(), raw == null ? "[error] no response" : raw);
        }
        List<LlmChain> chains = parseChains(raw);
        return new ChainAnalysis(chains, chains.isEmpty() ? "[no chains parsed] " + snippet(raw) : null);
    }

    static List<LlmChain> parseChains(String raw) {
        List<LlmChain> out = new ArrayList<>();
        String json = isolateJson(raw);
        if (json == null) return out;
        try {
            Object root = Json.parse(json);
            Map<String, Object> obj = Json.asObject(root);
            List<Object> arr = obj != null ? Json.asArray(obj.get("chains")) : Json.asArray(root);
            if (arr == null) return out;
            for (Object item : arr) {
                Map<String, Object> c = Json.asObject(item);
                if (c == null) continue;
                out.add(new LlmChain(
                        nz(Json.str(c, "title"), "Exploit chain"),
                        nz(Json.str(c, "severity"), "MEDIUM"),
                        nz(Json.str(c, "confidence"), "TENTATIVE"),
                        joinField(c, "primitives", "; "),
                        joinField(c, "steps", "\n"),
                        nz(Json.str(c, "impact"), ""),
                        nz(Json.str(c, "writeup"), ""),
                        joinField(c, "involved_urls", ", ")));
            }
        } catch (Exception ignored) {
            // malformed JSON -> caller falls back to the raw error message
        }
        return out;
    }

    /** Reads a field that may be a JSON string or a JSON array of strings, joined with {@code sep}. */
    private static String joinField(Map<String, Object> obj, String key, String sep) {
        Object v = obj.get(key);
        List<Object> arr = Json.asArray(v);
        if (arr != null) {
            List<String> parts = new ArrayList<>();
            for (Object e : arr) if (e != null) parts.add(String.valueOf(e).strip());
            return String.join(sep, parts);
        }
        return v == null ? "" : String.valueOf(v).strip();
    }

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
