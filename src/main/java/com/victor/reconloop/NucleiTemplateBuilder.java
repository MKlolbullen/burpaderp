package com.victor.reconloop;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

/**
 * Turns a <em>confirmed</em> active finding into a runnable Nuclei v3 YAML template — a portable,
 * CI-runnable proof-of-concept that re-proves the issue, attached to the native Burp issue. Unlike the
 * LLM Nuclei-template feature (which authors from a natural-language description), this is deterministic:
 * a confirmed class at a known URL/parameter maps to a fixed payload and an in-band matcher.
 *
 * <p>Everything here is pure and unit-tested. This first slice covers query-parameter injection points
 * for the in-band-confirmable classes; out-of-band/blind classes (SSRF, blind XSS, command injection,
 * host-header) need Nuclei's interactsh support, and header/path/JSON insertion points need a raw
 * request — both are follow-ups, so {@link #fromActiveFinding} returns empty for them rather than
 * emitting a template that wouldn't actually reproduce the finding.
 */
final class NucleiTemplateBuilder {

    private NucleiTemplateBuilder() {}

    enum MatcherKind { WORD, REGEX, DSL }

    /**
     * A fully-resolved PoC: {@code targetUrl} already has the payload placed at the injection point, and
     * the matcher is what confirms the class in-band. {@code matcherPart} is {@code body} or {@code header}.
     */
    record PocSpec(String id, String name, String severity, String targetUrl,
                   MatcherKind matcherKind, String matcherPart, String matcherValue) {}

    /**
     * Builds a {@link PocSpec} from a confirmed active finding, or empty when this slice can't faithfully
     * reproduce it (a non-query-parameter injection point, or a class with no in-band matcher).
     *
     * @param testClass      the {@code ActiveFinding} class (e.g. {@code SQLi})
     * @param severity       the finding severity (HIGH/MEDIUM/LOW)
     * @param url            the finding URL (the request that was probed)
     * @param injectionPoint the insertion-point label (a bare parameter name here; {@code header:}/
     *                       {@code path[}/{@code json:} labels are not query params and return empty)
     * @param evidence       the finding's evidence text, used to gate classes with several confirmation
     *                       vectors (SQLi, SSTI) so a template is only emitted when the fixed payload
     *                       and matcher actually reproduce the vector that confirmed <em>this</em> finding
     */
    static Optional<PocSpec> fromActiveFinding(String testClass, String severity, String url,
                                               String injectionPoint, String evidence) {
        if (testClass == null || url == null || injectionPoint == null) return Optional.empty();
        // Only bare query/body parameter names are handled in this slice.
        if (injectionPoint.startsWith("header:") || injectionPoint.startsWith("path[")
                || injectionPoint.startsWith("json:") || injectionPoint.isBlank()) {
            return Optional.empty();
        }
        String ev = evidence == null ? "" : evidence;

        String payload;
        MatcherKind kind;
        String part;
        String matcher;
        switch (testClass) {
            case "SQLi" -> {
                // Only error-based SQLi is reproduced by an error-signature body matcher; a
                // boolean- or time-based confirmation is not, so don't emit a template that would fail.
                if (!ev.toLowerCase(Locale.ROOT).contains("error signature")) return Optional.empty();
                payload = "'"; kind = MatcherKind.REGEX; part = "body";
                matcher = "(?i)sql syntax|mysql_fetch|ORA-[0-9]{4,5}|PostgreSQL.*ERROR|SQLite/JDBCDriver|"
                        + "Unclosed quotation mark|quoted string not properly terminated";
            }
            case "NoSQLi" -> {
                payload = "'\""; kind = MatcherKind.REGEX; part = "body";
                matcher = "(?i)MongoError|MongoServerError|BSON|E11000 duplicate key|Cast to ObjectId failed|\\$where";
            }
            case "SSTI" -> {
                // The {{7*777}} payload only reproduces the brace family; a ${...}/#{...}/<%=%> engine
                // (named in the evidence) would not evaluate it, so gate on the confirmed family.
                if (!ev.contains("{{")) return Optional.empty();
                payload = "rhs{{7*777}}she"; kind = MatcherKind.WORD; part = "body";
                matcher = "rhs5439she"; // the distinctive product marker ActiveTestEngine confirms on
            }
            case "PathTraversal" -> {
                payload = "../../../../../../etc/passwd"; kind = MatcherKind.REGEX; part = "body";
                matcher = "root:[^:\\r\\n]{0,64}:0:0:";
            }
            case "OpenRedirect" -> {
                payload = "https://rh-redirect.example.net/"; kind = MatcherKind.WORD; part = "header";
                matcher = "rh-redirect.example.net"; // reflected into the Location header
            }
            case "CRLF" -> {
                payload = "rhcrlf%0d%0aX-Recon-Hound%3a%20injected"; kind = MatcherKind.WORD; part = "header";
                matcher = "X-Recon-Hound"; // injected response header
            }
            case "XSS" -> {
                payload = "rhxprobe\"><img src=rhx>"; kind = MatcherKind.WORD; part = "body";
                matcher = "rhxprobe\"><img src=rhx>"; // reflected unencoded
            }
            default -> {
                return Optional.empty(); // OOB/blind and everything else: no in-band matcher
            }
        }

        String targetUrl = withQueryParam(url, injectionPoint, payload);
        String id = "recon-hound-" + slug(testClass) + "-" + shortHash(targetUrl + matcher);
        String name = testClass + " via " + injectionPoint + " (Recon Hound PoC)";
        return Optional.of(new PocSpec(id, name, normaliseSeverity(severity), targetUrl, kind, part, matcher));
    }

    /** Renders a {@link PocSpec} as a self-contained Nuclei v3 template. */
    static String build(PocSpec spec) {
        String valuesKey = switch (spec.matcherKind()) {
            case WORD -> "words";
            case REGEX -> "regex";
            case DSL -> "dsl";
        };
        return "id: " + spec.id() + "\n"
                + "info:\n"
                + "  name: " + yaml(spec.name()) + "\n"
                + "  author: recon-hound\n"
                + "  severity: " + spec.severity() + "\n"
                + "  description: " + yaml("Auto-generated by Recon Hound to re-prove a confirmed active finding. "
                        + "Verify against an authorised target only.") + "\n"
                + "  tags: recon-hound,poc\n"
                + "http:\n"
                + "  - method: GET\n"
                + "    redirects: false\n"
                + "    path:\n"
                + "      - " + yaml(spec.targetUrl()) + "\n"
                + "    matchers:\n"
                + "      - type: " + spec.matcherKind().name().toLowerCase(Locale.ROOT) + "\n"
                + "        part: " + spec.matcherPart() + "\n"
                + "        " + valuesKey + ":\n"
                + "          - " + yaml(spec.matcherValue()) + "\n";
    }

    // ---- pure helpers ----

    /** Sets (or appends) {@code param=urlencoded(value)} in {@code url}'s query string, preserving any fragment. */
    static String withQueryParam(String url, String param, String value) {
        String enc = urlEncode(value);
        int hash = url.indexOf('#');
        String fragment = hash >= 0 ? url.substring(hash) : "";
        String base = hash >= 0 ? url.substring(0, hash) : url;

        int q = base.indexOf('?');
        if (q < 0) return base + "?" + param + "=" + enc + fragment;

        String path = base.substring(0, q);
        String query = base.substring(q + 1);
        StringBuilder rebuilt = new StringBuilder();
        boolean replaced = false;
        if (!query.isEmpty()) {
            for (String pair : query.split("&", -1)) {
                int eq = pair.indexOf('=');
                String key = eq >= 0 ? pair.substring(0, eq) : pair;
                if (rebuilt.length() > 0) rebuilt.append('&');
                if (key.equals(param)) { rebuilt.append(param).append('=').append(enc); replaced = true; }
                else rebuilt.append(pair);
            }
        }
        if (!replaced) {
            if (rebuilt.length() > 0) rebuilt.append('&');
            rebuilt.append(param).append('=').append(enc);
        }
        return path + "?" + rebuilt + fragment;
    }

    private static String urlEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** Double-quoted YAML scalar with the minimal escaping a double-quoted scalar needs. */
    static String yaml(String value) {
        String v = value == null ? "" : value;
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.append('"').toString();
    }

    private static String slug(String value) {
        String s = value.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
        return s.isEmpty() ? "finding" : s;
    }

    private static String shortHash(String value) {
        return String.format("%08x", value.hashCode());
    }

    private static String normaliseSeverity(String severity) {
        if (severity == null) return "info";
        String s = severity.toLowerCase(Locale.ROOT);
        return switch (s) {
            case "high", "medium", "low", "critical", "info" -> s;
            default -> "info";
        };
    }
}
