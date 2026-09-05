package com.victor.reconloop;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * One location in an HTTP request where an active probe can inject a payload — a query or body
 * parameter, or a fuzzable request header. Enumerating these lets every probe cover more of the
 * attack surface than the old parameter-only loop (header-borne SSRF, SQLi in {@code User-Agent},
 * command injection via {@code X-Forwarded-For}, …) without each probe knowing how a point is applied.
 *
 * <p>{@link #apply} is the only Montoya-facing method; the header allow-list and labelling are pure and
 * unit-tested. {@code baseValue} is the point's current value — the baseline a differencing probe
 * (SQLi/NoSQL/path traversal) sends first and diffs against.
 *
 * <p>Cookies are intentionally excluded (a mutated session cookie usually just breaks auth), and only a
 * curated allow-list of headers is fuzzed so probes never rewrite {@code Host}, {@code Content-Length},
 * {@code Authorization}, or other headers that would malform the request or lose the session. Path
 * segments and JSON body values are a planned follow-up (they need path-encoding / JSON re-serialisation).
 */
record InsertionPoint(Kind kind, String name, String baseValue, HttpParameterType paramType) {

    enum Kind { PARAM, HEADER }

    /**
     * Request headers worth fuzzing: ones an application commonly trusts or reflects (client-IP /
     * forwarding spoofs, overrides, UA/Referer reflection). Deliberately excludes transport and auth
     * headers (Host, Content-Length, Authorization, Cookie, …) whose mutation breaks the request.
     */
    private static final Set<String> FUZZABLE_HEADERS = Set.of(
            "user-agent", "referer", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
            "x-forwarded-server", "x-real-ip", "x-client-ip", "true-client-ip", "cf-connecting-ip",
            "forwarded", "x-original-url", "x-rewrite-url", "x-http-method-override", "x-api-version");

    /** True when {@code headerName} is on the curated fuzzable allow-list (case-insensitive). */
    static boolean isFuzzableHeader(String headerName) {
        return headerName != null && FUZZABLE_HEADERS.contains(headerName.trim().toLowerCase(Locale.ROOT));
    }

    /** Short label used in findings and OOB correlation, e.g. {@code q} or {@code header:X-Forwarded-For}. */
    String label() {
        return kind == Kind.HEADER ? "header:" + name : name;
    }

    /** Builds {@code base} with this point set to {@code value}. The only Montoya-facing method here. */
    HttpRequest apply(HttpRequest base, String value) {
        return kind == Kind.HEADER
                ? base.withUpdatedHeader(name, value)
                : base.withUpdatedParameters(HttpParameter.parameter(name, value, paramType));
    }

    /**
     * Enumerates the injectable points of {@code base}: URL and body parameters (cookies skipped), then
     * fuzzable headers. Parameters come first so they are exercised before the request budget is spent.
     */
    static List<InsertionPoint> enumerate(HttpRequest base) {
        List<InsertionPoint> points = new ArrayList<>();
        if (base == null) return points;

        try {
            for (HttpParameter parameter : base.parameters()) {
                if (parameter == null || parameter.name() == null || parameter.name().isBlank()) continue;
                HttpParameterType type = parameter.type();
                if (type == HttpParameterType.URL || type == HttpParameterType.BODY) {
                    points.add(new InsertionPoint(Kind.PARAM, parameter.name(), parameter.value(), type));
                }
            }
        } catch (Exception ignored) {
            // A request whose parameters can't be parsed still yields its header points below.
        }

        try {
            for (HttpHeader header : base.headers()) {
                if (header == null || !isFuzzableHeader(header.name())) continue;
                points.add(new InsertionPoint(Kind.HEADER, header.name(), header.value(), null));
            }
        } catch (Exception ignored) {
            // No headers enumerable — return whatever parameter points were found.
        }

        return points;
    }
}
