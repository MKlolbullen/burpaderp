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

    /**
     * Deep enough to enumerate field/argument/enum names (not just top-level type kinds), so
     * {@link #analyzeIntrospection} can flag sensitive-sounding mutations and fields by name —
     * mapping exactly which dangerous operations exist before an attacker ever calls one.
     */
    static String introspectionQuery() {
        return "{\"query\":\"query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
                + "subscriptionType { name } types { ...FullType } } } "
                + "fragment FullType on __Type { kind name fields(includeDeprecated: true) { name args { name } "
                + "type { name kind ofType { name kind } } isDeprecated deprecationReason } inputFields { name } "
                + "interfaces { name } enumValues(includeDeprecated: true) { name isDeprecated } possibleTypes { name } }\"}";
    }

    private static final Pattern SCHEMA_NAME = Pattern.compile("\"name\"\\s*:\\s*\"([A-Za-z_][A-Za-z0-9_]*)\"");

    /** Field/argument/mutation names whose presence in a schema is worth flagging on its own. */
    private static final Set<String> SENSITIVE_NAME_HINTS = Set.of(
            "password", "secret", "token", "apikey", "admin", "delete", "remove", "impersonate",
            "internal", "debug", "resetpassword", "changerole", "grantrole", "sudo", "superuser",
            "privilege", "bypass");

    record IntrospectionDetail(boolean enabled, int typeCount, boolean mutationsPresent, List<String> sensitiveNames) {}

    /** Parses an introspection response into whether it's enabled, rough size, and sensitive-sounding names. */
    static IntrospectionDetail analyzeIntrospection(String body) {
        if (body == null || !body.contains("__schema")) return new IntrospectionDetail(false, 0, false, List.of());

        int types = countOccurrences(body, "\"kind\"");
        boolean mutations = body.contains("\"mutationType\"") && !body.contains("\"mutationType\":null");

        LinkedHashSet<String> sensitive = new LinkedHashSet<>();
        Matcher matcher = SCHEMA_NAME.matcher(body);
        while (matcher.find()) {
            String name = matcher.group(1);
            String lower = name.toLowerCase(Locale.ROOT);
            for (String hint : SENSITIVE_NAME_HINTS) {
                if (lower.contains(hint)) { sensitive.add(name); break; }
            }
        }
        return new IntrospectionDetail(true, types, mutations, List.copyOf(sensitive));
    }

    /** Human-readable one-line summary of an {@link IntrospectionDetail}. */
    static String describe(IntrospectionDetail detail) {
        if (!detail.enabled()) return "introspection appears disabled (no __schema in response)";
        StringBuilder summary = new StringBuilder("introspection ENABLED — ~" + detail.typeCount() + " types exposed");
        if (detail.mutationsPresent()) summary.append(", mutations present");
        if (!detail.sensitiveNames().isEmpty()) {
            summary.append(", sensitive-sounding fields: ").append(String.join(", ", detail.sensitiveNames()));
        }
        return summary.toString();
    }

    private static final Pattern EMPTY_SECURITY = Pattern.compile("\"security\"\\s*:\\s*\\[\\s*]");

    /** True if the spec declares a top-level (default) security requirement, outside the paths block. */
    static boolean hasGlobalSecurityRequirement(String body) {
        if (body == null) return false;
        int pathsAt = body.indexOf("\"paths\"");
        if (pathsAt < 0) return body.contains("\"security\"");
        int brace = body.indexOf('{', pathsAt);
        int end = brace < 0 ? -1 : matchingBrace(body, brace);
        String outsidePaths = end < 0 ? body.substring(0, pathsAt) : body.substring(0, pathsAt) + body.substring(end);
        return outsidePaths.contains("\"security\"");
    }

    /**
     * Resolves every operation that explicitly sets {@code "security": []} — an unambiguous, deliberate
     * opt-out from whatever default authentication the spec otherwise requires, and a common source of
     * accidental BOLA/IDOR when that opt-out wasn't actually intended for the endpoint it landed on.
     * Attributed to the nearest preceding path key, so it's only as reliable as the spec's own nesting.
     */
    static Set<String> findAuthOptOutOperations(String body, URI base) {
        if (body == null || base == null) return Set.of();
        int pathsAt = body.indexOf("\"paths\"");
        if (pathsAt < 0) return Set.of();
        int brace = body.indexOf('{', pathsAt);
        if (brace < 0) return Set.of();
        int end = matchingBrace(body, brace);
        String pathsBlock = body.substring(brace, end < 0 ? body.length() : end);

        List<Integer> pathIndices = new ArrayList<>();
        List<String> pathNames = new ArrayList<>();
        Matcher pathMatcher = PATH_KEY.matcher(pathsBlock);
        while (pathMatcher.find()) {
            pathIndices.add(pathMatcher.start());
            pathNames.add(pathMatcher.group(1).replaceAll("\\{[^}]*}", "1"));
        }

        TreeSet<String> results = new TreeSet<>();
        Matcher secMatcher = EMPTY_SECURITY.matcher(pathsBlock);
        while (secMatcher.find()) {
            int at = secMatcher.start();
            String owningPath = null;
            for (int i = 0; i < pathIndices.size(); i++) {
                if (pathIndices.get(i) <= at) owningPath = pathNames.get(i);
                else break;
            }
            if (owningPath != null) {
                try { results.add(base.resolve(owningPath).toString()); } catch (Exception ignored) {}
            }
        }
        return results;
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
