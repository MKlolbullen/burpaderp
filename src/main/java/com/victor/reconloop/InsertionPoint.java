package com.victor.reconloop;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * One location in an HTTP request where an active probe can inject a payload — a request parameter
 * (any type except a cookie), a fuzzable header, a URL path segment, or a value inside a JSON body.
 * Enumerating these lets every active probe cover the whole request surface without knowing how a
 * point is applied: {@link #apply} is the only Montoya-facing method, and the allow-list, path, and
 * JSON substitution helpers are pure and unit-tested.
 *
 * <p>{@code baseValue} is the point's current value — the baseline a differencing probe (SQLi/NoSQL/
 * path traversal) sends first and diffs against (empty for a header the request omits).
 *
 * <p>Cookies are excluded (a mutated session cookie usually breaks auth), and only a curated allow-list
 * of headers is fuzzed so probes never rewrite {@code Host}, {@code Authorization}, etc. Path-segment
 * payloads are percent-encoded so they can't malform the request line; JSON payloads are set into the
 * parsed body which is then re-serialised.
 */
record InsertionPoint(Kind kind, String name, String baseValue, HttpParameterType paramType, int index) {

    enum Kind { PARAM, HEADER, PATH, JSON }

    /** Convenience for the non-path kinds (path segments use the {@code index} overload). */
    InsertionPoint(Kind kind, String name, String baseValue, HttpParameterType paramType) {
        this(kind, name, baseValue, paramType, -1);
    }

    /**
     * Headers worth fuzzing (canonical casing): ones an application commonly trusts or reflects. Each is
     * probed whether or not the captured request carried it, since the classic bug is an endpoint that
     * trusts an <em>absent</em> header once supplied. Transport/auth headers are deliberately excluded.
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

    /**
     * Short label for findings/correlation, e.g. {@code q}, {@code header:X-Forwarded-For},
     * {@code path[2]}, or {@code json:/user/role}.
     */
    String label() {
        return switch (kind) {
            case HEADER -> "header:" + name;
            case PATH -> "path[" + index + "]";
            case JSON -> "json:" + name;
            case PARAM -> name;
        };
    }

    /** Builds {@code base} with this point set to {@code value}. The only Montoya-facing method here. */
    HttpRequest apply(HttpRequest base, String value) {
        return switch (kind) {
            case HEADER -> base.withUpdatedHeader(name, value);
            case PARAM -> base.withUpdatedParameters(HttpParameter.parameter(name, value, paramType));
            case PATH -> base.withPath(
                    replacePathSegment(base.pathWithoutQuery(), index, encodePathSegment(value))
                            + querySuffix(base.path()));
            case JSON -> base.withBody(setJsonLeaf(base.bodyToString(), name, value));
        };
    }

    /**
     * Enumerates the injectable points of {@code base}: every non-cookie parameter, then JSON body
     * values, then URL path segments, then the fuzzable-header allow-list. The request's own inputs
     * (params, body, path) come before headers so they are exercised before the budget is spent; a
     * header the request omits is still enumerated (empty base value) so trusted-but-absent headers
     * get probed.
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
            // fall through to the other point kinds
        }

        addJsonPoints(base, points);
        addPathPoints(base, points);

        Map<String, String> presentHeaders = new HashMap<>(); // lower-cased name -> current value
        try {
            for (HttpHeader header : base.headers()) {
                if (header == null || header.name() == null) continue;
                presentHeaders.putIfAbsent(header.name().toLowerCase(Locale.ROOT), header.value());
            }
        } catch (Exception ignored) {
            // still probe the allow-list with empty base values below
        }
        for (String name : FUZZABLE_HEADERS) {
            String existing = presentHeaders.get(name.toLowerCase(Locale.ROOT));
            points.add(new InsertionPoint(Kind.HEADER, name, existing == null ? "" : existing, null));
        }

        return points;
    }

    private static void addJsonPoints(HttpRequest base, List<InsertionPoint> points) {
        String body;
        try {
            body = base.bodyToString();
        } catch (Exception e) {
            return;
        }
        if (!looksLikeJson(headerValue(base, "Content-Type"), body)) return;
        try {
            Object tree = Json.parse(body);
            for (String pointer : Json.leafPointers(tree)) {
                Object leaf = Json.getByPointer(tree, pointer);
                points.add(new InsertionPoint(Kind.JSON, pointer, String.valueOf(leaf), null));
            }
        } catch (Exception ignored) {
            // not valid JSON after all — no JSON points
        }
    }

    private static void addPathPoints(HttpRequest base, List<InsertionPoint> points) {
        String path;
        try {
            path = base.pathWithoutQuery();
        } catch (Exception e) {
            return;
        }
        if (path == null || path.isEmpty()) return;
        String[] parts = path.split("/", -1);
        for (int i = 0; i < parts.length; i++) {
            if (parts[i].isEmpty()) continue; // skip the empty token before a leading / or after a trailing /
            points.add(new InsertionPoint(Kind.PATH, parts[i], parts[i], null, i));
        }
    }

    /** True when the body is (or is declared to be) JSON: a {@code json} content-type or a {@code {}/[} opener. */
    static boolean looksLikeJson(String contentType, String body) {
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json")) return true;
        if (body == null) return false;
        String trimmed = body.stripLeading();
        return trimmed.startsWith("{") || trimmed.startsWith("[");
    }

    /** Replaces path-array element {@code index} (from {@code pathWithoutQuery.split("/")}) with {@code value}. */
    static String replacePathSegment(String pathWithoutQuery, int index, String value) {
        if (pathWithoutQuery == null) return "";
        String[] parts = pathWithoutQuery.split("/", -1);
        if (index < 0 || index >= parts.length) return pathWithoutQuery;
        parts[index] = value;
        return String.join("/", parts);
    }

    /** The {@code ?query} suffix of a full request path, or "" if none. */
    static String querySuffix(String fullPath) {
        if (fullPath == null) return "";
        int q = fullPath.indexOf('?');
        return q >= 0 ? fullPath.substring(q) : "";
    }

    /** Percent-encodes {@code value} for use as a single URL path segment (RFC-3986 unreserved kept). */
    static String encodePathSegment(String value) {
        if (value == null || value.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (byte raw : value.getBytes(StandardCharsets.UTF_8)) {
            int c = raw & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%')
                        .append(Character.toUpperCase(Character.forDigit((c >> 4) & 0xf, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return sb.toString();
    }

    /** Parses {@code body}, sets the leaf at {@code pointer} to {@code value}, and re-serialises; the original body on failure. */
    static String setJsonLeaf(String body, String pointer, String value) {
        try {
            Object tree = Json.parse(body);
            if (Json.setByPointer(tree, pointer, value)) return Json.write(tree);
        } catch (Exception ignored) {
            // fall through
        }
        return body == null ? "" : body;
    }

    private static String headerValue(HttpRequest base, String name) {
        try {
            return base.headerValue(name);
        } catch (Exception e) {
            return null;
        }
    }
}
