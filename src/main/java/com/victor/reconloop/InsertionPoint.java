package com.victor.reconloop;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * One location in an HTTP request where an active probe can inject a payload — a request parameter
 * (any type except a cookie) or a fuzzable header. Enumerating these lets every active probe cover
 * more of the attack surface than the old parameter-only loop (header-borne SSRF, SQLi in
 * {@code User-Agent}, command injection via {@code X-Forwarded-For}, …) without each probe knowing how
 * a point is applied.
 *
 * <p>{@link #apply} is the only Montoya-facing method; the header allow-list and labelling are pure and
 * unit-tested. {@code baseValue} is the point's current value — the baseline a differencing probe
 * (SQLi/NoSQL/path traversal) sends first and diffs against (empty for a header the request omits).
 *
 * <p>Cookies are intentionally excluded (a mutated session cookie usually just breaks auth), and only a
 * curated allow-list of headers is fuzzed so probes never rewrite {@code Host}, {@code Content-Length},
 * {@code Authorization}, or other headers whose mutation would malform the request or lose the session.
 * Path segments and JSON body values are a planned follow-up (they need path-encoding / JSON
 * re-serialisation).
 */
record InsertionPoint(Kind kind, String name, String baseValue, HttpParameterType paramType) {

    enum Kind { PARAM, HEADER }

    /**
     * Headers worth fuzzing (canonical casing): ones an application commonly trusts or reflects —
     * client-IP / forwarding spoofs, URL/method overrides, UA/Referer reflection. Each is probed
     * whether or not the captured request already carried it, since the classic bug is an endpoint
     * that trusts an <em>absent</em> header once it is supplied. Transport and auth headers (Host,
     * Content-Length, Authorization, Cookie, …) are deliberately excluded.
     */
    private static final List<String> FUZZABLE_HEADERS = List.of(
            "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Forwarded-Server",
            "X-Real-IP", "X-Client-IP", "True-Client-IP", "CF-Connecting-IP", "Forwarded",
            "X-Original-URL", "X-Rewrite-URL", "X-Http-Method-Override", "X-Api-Version",
            "User-Agent", "Referer");

    private static final Set<String> FUZZABLE_HEADER_KEYS;
    static {
        Set<String> keys = new HashSet<>();
        for (String name : FUZZABLE_HEADERS) keys.add(name.toLowerCase(Locale.ROOT));
        FUZZABLE_HEADER_KEYS = Set.copyOf(keys);
    }

    /** True when {@code headerName} is on the curated fuzzable allow-list (case-insensitive). */
    static boolean isFuzzableHeader(String headerName) {
        return headerName != null && FUZZABLE_HEADER_KEYS.contains(headerName.trim().toLowerCase(Locale.ROOT));
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
     * Enumerates the injectable points of {@code base}: every non-cookie parameter (URL, body, JSON,
     * XML, multipart — whatever Montoya parsed), then the full fuzzable-header allow-list. Parameters
     * come first so they are exercised before the request budget is spent; a header the request omits
     * is still enumerated (with an empty base value) so trusted-but-absent headers get probed.
     */
    static List<InsertionPoint> enumerate(HttpRequest base) {
        List<InsertionPoint> points = new ArrayList<>();
        if (base == null) return points;

        try {
            for (HttpParameter parameter : base.parameters()) {
                if (parameter == null || parameter.name() == null || parameter.name().isBlank()) continue;
                if (parameter.type() == HttpParameterType.COOKIE) continue; // mutating a session cookie breaks auth
                points.add(new InsertionPoint(Kind.PARAM, parameter.name(), parameter.value(), parameter.type()));
            }
        } catch (Exception ignored) {
            // A request whose parameters can't be parsed still yields its header points below.
        }

        Map<String, String> presentHeaders = new HashMap<>(); // lower-cased name -> current value
        try {
            for (HttpHeader header : base.headers()) {
                if (header == null || header.name() == null) continue;
                presentHeaders.putIfAbsent(header.name().toLowerCase(Locale.ROOT), header.value());
            }
        } catch (Exception ignored) {
            // No headers enumerable — still probe the allow-list with empty base values below.
        }
        for (String name : FUZZABLE_HEADERS) {
            String existing = presentHeaders.get(name.toLowerCase(Locale.ROOT));
            points.add(new InsertionPoint(Kind.HEADER, name, existing == null ? "" : existing, null));
        }

        return points;
    }
}
