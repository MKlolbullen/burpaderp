package com.victor.reconloop;

import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Passive reflected-XSS surface mapper.
 *
 * <p>For every in-scope response whose initiating request carried parameters, this engine looks for
 * request parameter values that are echoed verbatim into the response body. When a value is
 * reflected it classifies the <em>reflection context</em> (HTML text, quoted/unquoted attribute,
 * URL attribute, inline script string/block, style block, comment, RCDATA) and reports which
 * XSS-relevant metacharacters survived unencoded at the reflection point.
 *
 * <p>The engine never injects anything: it only observes what the target already sent back. The
 * detected context plus the set of surviving characters is what {@link XssVectorLibrary} uses to
 * suggest the cheat-sheet vectors that are actually viable for a given sink.
 */
final class XssReflectionEngine {

    /** Ordered by decreasing directness of exploitation for a given surviving character set. */
    enum Context {
        HTML_TEXT("HTML element text", "<>"),
        HTML_COMMENT("HTML comment", "<>"),
        RCDATA("RCDATA element (title/textarea)", "<>"),
        HTML_ATTR_DOUBLE("Double-quoted HTML attribute", "\""),
        HTML_ATTR_SINGLE("Single-quoted HTML attribute", "'"),
        HTML_ATTR_UNQUOTED("Unquoted HTML attribute", " "),
        URL_ATTRIBUTE("URL attribute (href/src/action)", ":"),
        SCRIPT_STRING_DOUBLE("Double-quoted JavaScript string", "\""),
        SCRIPT_STRING_SINGLE("Single-quoted JavaScript string", "'"),
        SCRIPT_TEMPLATE("JavaScript template literal", "`"),
        SCRIPT_BLOCK("Inline <script> block", ""),
        STYLE_BLOCK("Inline <style> block", "<"),
        UNKNOWN("Generic / unknown", "");

        private final String label;
        private final String breakoutHint;

        Context(String label, String breakoutHint) {
            this.label = label;
            this.breakoutHint = breakoutHint;
        }

        String label() { return label; }
        String breakoutHint() { return breakoutHint; }
    }

    record Reflection(
            String parameter,
            String type,
            String valuePreview,
            Context context,
            String survivingChars,
            String severity,
            int occurrences,
            List<XssVectorLibrary.Vector> viableVectors,
            String url,
            int start,
            int end) {}

    /** XSS-relevant metacharacters whose survival we track at the reflection point. */
    private static final char[] DANGEROUS = {'<', '>', '"', '\'', '`', '(', ')', '{', '}', ';', '=', '/', '\\'};

    private static final Set<String> URL_ATTRIBUTES = Set.of(
            "href", "src", "action", "formaction", "data", "poster", "background",
            "xlink:href", "ping", "srcset", "cite", "manifest");

    private static final int MAX_BODY = 3_000_000;
    private static final int MAX_BACKSCAN = 8_192;
    private static final int MAX_OCCURRENCES = 8;
    private static final int MIN_VALUE_LENGTH = 4;
    private static final int MAX_VALUE_LENGTH = 512;

    List<Reflection> analyze(HttpRequest request, HttpResponse response) {
        if (request == null || response == null) return List.of();
        if (!looksRenderable(response)) return List.of();

        String body = response.bodyToString();
        if (body == null || body.isEmpty()) return List.of();
        if (body.length() > MAX_BODY) body = body.substring(0, MAX_BODY);
        int bodyOffset = response.bodyOffset();

        List<HttpParameter> parameters;
        try {
            parameters = new ArrayList<>(request.parameters());
        } catch (Exception e) {
            return List.of();
        }

        List<Reflection> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (HttpParameter parameter : parameters) {
            if (parameter == null) continue;
            String type = String.valueOf(parameter.type());
            if ("COOKIE".equalsIgnoreCase(type)) continue;

            String name = parameter.name() == null ? "" : parameter.name();
            if (name.isBlank()) continue;

            for (String candidate : candidateValues(parameter.value())) {
                if (!interesting(candidate)) continue;

                List<Integer> positions = occurrences(body, candidate);
                if (positions.isEmpty()) continue;

                Context context = classify(body, positions.get(0));
                String surviving = survivingDangerous(candidate);
                String severity = severityFor(context, surviving);
                List<XssVectorLibrary.Vector> vectors =
                        XssVectorLibrary.suggest(context, surviving);

                String dedupe = name + "\0" + type + "\0" + context;
                if (!seen.add(dedupe)) continue;

                int start = bodyOffset + positions.get(0);
                int end = start + candidate.length();
                out.add(new Reflection(
                        name, type, preview(candidate), context, surviving,
                        severity, positions.size(), vectors, request.url(), start, end));
            }
        }
        return out;
    }

    private static boolean looksRenderable(HttpResponse response) {
        String contentType = response.headerValue("Content-Type");
        if (contentType == null || contentType.isBlank()) return true;
        String lower = contentType.toLowerCase(Locale.ROOT);
        return lower.contains("html")
                || lower.contains("xml")
                || lower.contains("javascript")
                || lower.contains("ecmascript")
                || lower.startsWith("text/plain");
    }

    private static List<String> candidateValues(String raw) {
        if (raw == null) return List.of();
        LinkedHashSet<String> values = new LinkedHashSet<>();
        values.add(raw);
        try {
            String decoded = URLDecoder.decode(raw.replace("+", "%2B"), StandardCharsets.UTF_8);
            values.add(decoded);
        } catch (Exception ignored) {}
        return new ArrayList<>(values);
    }

    private static boolean interesting(String value) {
        if (value == null) return false;
        int length = value.length();
        if (length < MIN_VALUE_LENGTH || length > MAX_VALUE_LENGTH) return false;
        boolean hasLetter = false;
        for (int i = 0; i < length; i++) {
            if (Character.isLetter(value.charAt(i))) { hasLetter = true; break; }
        }
        return hasLetter;
    }

    private static List<Integer> occurrences(String body, String value) {
        List<Integer> positions = new ArrayList<>();
        int from = 0;
        while (positions.size() < MAX_OCCURRENCES) {
            int index = body.indexOf(value, from);
            if (index < 0) break;
            positions.add(index);
            from = index + value.length();
        }
        return positions;
    }

    private static String survivingDangerous(String value) {
        StringBuilder builder = new StringBuilder();
        for (char c : DANGEROUS) {
            if (value.indexOf(c) >= 0) builder.append(c);
        }
        return builder.toString();
    }

    private static String severityFor(Context context, String surviving) {
        boolean tagBreak = surviving.indexOf('<') >= 0 && surviving.indexOf('>') >= 0;
        switch (context) {
            case HTML_TEXT, HTML_COMMENT, RCDATA, STYLE_BLOCK:
                return tagBreak ? "HIGH" : "LOW";
            case HTML_ATTR_DOUBLE:
                return surviving.indexOf('"') >= 0 ? "HIGH" : "LOW";
            case HTML_ATTR_SINGLE:
                return surviving.indexOf('\'') >= 0 ? "HIGH" : "LOW";
            case HTML_ATTR_UNQUOTED:
                return surviving.indexOf('=') >= 0 || surviving.indexOf('>') >= 0 ? "HIGH" : "MEDIUM";
            case URL_ATTRIBUTE:
                return "MEDIUM";
            case SCRIPT_STRING_DOUBLE:
                return surviving.indexOf('"') >= 0 ? "HIGH" : "MEDIUM";
            case SCRIPT_STRING_SINGLE:
                return surviving.indexOf('\'') >= 0 ? "HIGH" : "MEDIUM";
            case SCRIPT_TEMPLATE:
                return surviving.indexOf('`') >= 0 || surviving.indexOf('$') >= 0 ? "HIGH" : "MEDIUM";
            case SCRIPT_BLOCK:
                return "HIGH";
            default:
                return tagBreak ? "MEDIUM" : "INFO";
        }
    }

    /** Classifies the parser context at {@code index} by bounded backward scanning. */
    private Context classify(String body, int index) {
        int scanFrom = Math.max(0, index - MAX_BACKSCAN);
        String region = body.substring(scanFrom, index);
        String lower = region.toLowerCase(Locale.ROOT);

        int openScript = lastOpenTag(lower, "script");
        int closeScript = lower.lastIndexOf("</script");
        if (openScript > closeScript) {
            return scriptStringContext(region.substring(afterTag(region, openScript)));
        }

        int openStyle = lastOpenTag(lower, "style");
        int closeStyle = lower.lastIndexOf("</style");
        if (openStyle > closeStyle) return Context.STYLE_BLOCK;

        int openComment = region.lastIndexOf("<!--");
        int closeComment = region.lastIndexOf("-->");
        if (openComment > closeComment) return Context.HTML_COMMENT;

        int lastLt = region.lastIndexOf('<');
        int lastGt = region.lastIndexOf('>');
        if (lastLt > lastGt) {
            return attributeContext(region.substring(lastLt));
        }

        int openTitle = lastOpenTag(lower, "title");
        int closeTitle = lower.lastIndexOf("</title");
        int openTextarea = lastOpenTag(lower, "textarea");
        int closeTextarea = lower.lastIndexOf("</textarea");
        if (openTitle > closeTitle || openTextarea > closeTextarea) return Context.RCDATA;

        return Context.HTML_TEXT;
    }

    /** Index of the last {@code <tagName} opening (word-boundary aware) in {@code lower}. */
    private static int lastOpenTag(String lower, String tagName) {
        String needle = "<" + tagName;
        int at = lower.lastIndexOf(needle);
        while (at >= 0) {
            int after = at + needle.length();
            if (after >= lower.length()) return at;
            char c = lower.charAt(after);
            if (!Character.isLetterOrDigit(c)) return at;
            at = lower.lastIndexOf(needle, at - 1);
        }
        return -1;
    }

    private static int afterTag(String region, int openIndex) {
        int close = region.indexOf('>', openIndex);
        return close < 0 ? openIndex : close + 1;
    }

    /** Determines JS-string vs code context from the script text preceding the reflection. */
    private Context scriptStringContext(String scriptText) {
        char quote = 0;
        boolean escaped = false;
        for (int i = 0; i < scriptText.length(); i++) {
            char c = scriptText.charAt(i);
            if (escaped) { escaped = false; continue; }
            if (c == '\\') { escaped = true; continue; }
            if (quote != 0) {
                if (c == quote) quote = 0;
            } else if (c == '"' || c == '\'' || c == '`') {
                quote = c;
            }
        }
        return switch (quote) {
            case '"' -> Context.SCRIPT_STRING_DOUBLE;
            case '\'' -> Context.SCRIPT_STRING_SINGLE;
            case '`' -> Context.SCRIPT_TEMPLATE;
            default -> Context.SCRIPT_BLOCK;
        };
    }

    /** Determines attribute quoting/URL-ness from the open-tag text preceding the reflection. */
    private Context attributeContext(String tagText) {
        char quote = 0;
        int quotedAttrStart = -1;
        int lastEquals = -1;
        for (int i = 0; i < tagText.length(); i++) {
            char c = tagText.charAt(i);
            if (quote != 0) {
                if (c == quote) quote = 0;
            } else if (c == '"' || c == '\'') {
                quote = c;
                quotedAttrStart = i;
            } else if (c == '=') {
                lastEquals = i;
            }
        }

        String attributeName = attributeNameBefore(tagText,
                quote != 0 ? quotedAttrStart : (lastEquals >= 0 ? lastEquals : tagText.length()));
        boolean urlAttribute = URL_ATTRIBUTES.contains(attributeName);

        if (quote == '"') return urlAttribute ? Context.URL_ATTRIBUTE : Context.HTML_ATTR_DOUBLE;
        if (quote == '\'') return urlAttribute ? Context.URL_ATTRIBUTE : Context.HTML_ATTR_SINGLE;
        if (lastEquals >= 0) return urlAttribute ? Context.URL_ATTRIBUTE : Context.HTML_ATTR_UNQUOTED;
        return Context.HTML_ATTR_UNQUOTED;
    }

    private static String attributeNameBefore(String tagText, int marker) {
        int i = Math.min(marker, tagText.length()) - 1;
        while (i >= 0 && (tagText.charAt(i) == '=' || Character.isWhitespace(tagText.charAt(i)))) i--;
        int end = i + 1;
        while (i >= 0) {
            char c = tagText.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == ':') i--;
            else break;
        }
        return tagText.substring(i + 1, Math.max(i + 1, end)).toLowerCase(Locale.ROOT);
    }

    private static String preview(String value) {
        String collapsed = value.replaceAll("\\s+", " ").trim();
        return collapsed.length() <= 100 ? collapsed : collapsed.substring(0, 97) + "...";
    }
}
