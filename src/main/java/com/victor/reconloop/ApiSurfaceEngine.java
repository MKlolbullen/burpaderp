package com.victor.reconloop;

import java.net.URI;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Expands API attack surface from machine-readable descriptions:
 *
 * <ul>
 *   <li><b>OpenAPI / Swagger</b> — passively extracts the documented {@code paths} and resolves them
 *       against the spec's origin so every declared endpoint enters discovery.</li>
 *   <li><b>GraphQL</b> — detects endpoints and, on demand, summarises an introspection response
 *       (whether introspection is enabled and how many types/queries/mutations are exposed).</li>
 * </ul>
 *
 * Parsing is dependency-free and tolerant; the extractors are pure and unit-tested.
 */
final class ApiSurfaceEngine {

    private static final Pattern PATH_KEY =
            Pattern.compile("\"(/[^\"{}]*(?:\\{[^\"}]*}[^\"]*)*)\"\\s*:");

    static boolean looksLikeOpenApi(String body) {
        if (body == null) return false;
        boolean marker = body.contains("\"swagger\"") || body.contains("\"openapi\"");
        return marker && body.contains("\"paths\"");
    }

    /** Resolves documented OpenAPI paths against {@code base}, substituting {id}-style templates. */
    static Set<String> extractOpenApiPaths(String body, URI base) {
        if (body == null || base == null) return Set.of();
        int pathsAt = body.indexOf("\"paths\"");
        if (pathsAt < 0) return Set.of();

        int brace = body.indexOf('{', pathsAt);
        if (brace < 0) return Set.of();
        int end = matchingBrace(body, brace);
        String pathsBlock = body.substring(brace, end < 0 ? body.length() : end);

        TreeSet<String> urls = new TreeSet<>();
        Matcher matcher = PATH_KEY.matcher(pathsBlock);
        while (matcher.find()) {
            String path = matcher.group(1).replaceAll("\\{[^}]*}", "1");
            try {
                urls.add(base.resolve(path).toString());
            } catch (Exception ignored) {}
        }
        return urls;
    }

    static boolean looksLikeGraphQlEndpoint(String url) {
        if (url == null) return false;
        String lower = url.toLowerCase(Locale.ROOT);
        return lower.contains("/graphql") || lower.contains("/gql") || lower.endsWith("graphql");
    }

    static String introspectionQuery() {
        return "{\"query\":\"query IntrospectionQuery { __schema { queryType { name } "
                + "mutationType { name } types { name kind } } }\"}";
    }

    /** Summarises an introspection response: whether it is enabled and rough type/operation counts. */
    static String summarizeIntrospection(String body) {
        if (body == null || !body.contains("__schema")) {
            return body != null && body.toLowerCase(Locale.ROOT).contains("introspection")
                    ? "introspection appears disabled (server rejected the query)"
                    : "no __schema in response (introspection likely disabled)";
        }
        int types = countOccurrences(body, "\"kind\"");
        boolean mutations = body.contains("\"mutationType\"") && !body.contains("\"mutationType\":null");
        return "introspection ENABLED — ~" + types + " types exposed"
                + (mutations ? ", mutations present" : "");
    }

    private static int matchingBrace(String text, int open) {
        int depth = 0;
        boolean inString = false;
        for (int i = open; i < text.length(); i++) {
            char c = text.charAt(i);
            if (inString) {
                if (c == '\\') i++;
                else if (c == '"') inString = false;
            } else if (c == '"') inString = true;
            else if (c == '{') depth++;
            else if (c == '}' && --depth == 0) return i + 1;
        }
        return -1;
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0, from = 0;
        while (true) {
            int at = haystack.indexOf(needle, from);
            if (at < 0) return count;
            count++;
            from = at + needle.length();
        }
    }

    private ApiSurfaceEngine() {}
}
