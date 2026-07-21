package com.victor.reconloop;

import java.util.*;

/**
 * Recovers original source from JavaScript source maps ({@code .map}) by reading the
 * {@code sources} / {@code sourcesContent} arrays. Recovered files are handed back to the
 * controller, which mines them for endpoints and secrets — the original source usually exposes far
 * more attack surface than the minified bundle.
 *
 * <p>Parsing is a purpose-built, dependency-free JSON string-array reader (source maps embed
 * arbitrary escaped JavaScript, so a naive split is not safe).
 */
final class SourceMapMiner {

    record Source(String name, String content) {}

    static boolean looksLikeSourceMap(String url, String contentType, String body) {
        if (url != null && url.toLowerCase(Locale.ROOT).contains(".map")) return true;
        if (contentType != null && contentType.toLowerCase(Locale.ROOT).contains("json")
                && body != null && body.contains("\"sourcesContent\"")) return true;
        if (body == null) return false;
        String head = body.stripLeading();
        return head.startsWith("{") && head.contains("\"version\"") && head.contains("\"sources\"")
                && head.contains("\"mappings\"");
    }

    static List<Source> parse(String json) {
        if (json == null || json.isBlank()) return List.of();
        List<String> names = parseStringArray(json, "\"sources\"");
        List<String> contents = parseStringArray(json, "\"sourcesContent\"");
        if (contents.isEmpty()) return List.of();

        List<Source> sources = new ArrayList<>();
        for (int i = 0; i < contents.size(); i++) {
            String content = contents.get(i);
            if (content == null || content.isBlank()) continue;
            String name = i < names.size() ? names.get(i) : "source_" + i;
            sources.add(new Source(name, content));
        }
        return sources;
    }

    /** Reads the JSON array of strings that follows {@code key}, honouring \\ and \" escapes. */
    private static List<String> parseStringArray(String json, String key) {
        int at = json.indexOf(key);
        if (at < 0) return List.of();
        int bracket = json.indexOf('[', at + key.length());
        if (bracket < 0) return List.of();

        List<String> values = new ArrayList<>();
        int i = bracket + 1;
        int depth = 1;
        while (i < json.length() && depth > 0) {
            char c = json.charAt(i);
            if (c == ']') { depth--; i++; continue; }
            if (c == '[') { depth++; i++; continue; }
            if (c == 'n' && json.startsWith("null", i)) { values.add(null); i += 4; continue; }
            if (c == '"') {
                StringBuilder builder = new StringBuilder();
                i++;
                while (i < json.length()) {
                    char d = json.charAt(i);
                    if (d == '\\' && i + 1 < json.length()) {
                        builder.append(unescape(json.charAt(i + 1)));
                        i += 2;
                    } else if (d == '"') {
                        i++;
                        break;
                    } else {
                        builder.append(d);
                        i++;
                    }
                }
                values.add(builder.toString());
            } else {
                i++;
            }
        }
        return values;
    }

    private static char unescape(char escaped) {
        return switch (escaped) {
            case 'n' -> '\n';
            case 'r' -> '\r';
            case 't' -> '\t';
            case 'b' -> '\b';
            case 'f' -> '\f';
            default -> escaped; // covers quote, backslash, slash; unicode escapes are left as-is (rare here)
        };
    }

    private SourceMapMiner() {}
}
