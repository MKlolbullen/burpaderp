package com.victor.reconloop;

import java.util.Locale;

/**
 * Active GraphQL fuzzing that goes beyond introspection. Even with introspection disabled, servers
 * often leak schema via "Did you mean" field suggestions, and many accept query batching / field
 * aliasing that lets an attacker amplify a single request (rate-limit bypass, brute force, DoS).
 * These are pure request builders + response classifiers; the controller sends them.
 */
final class GraphQlFuzzEngine {

    /** A deliberately invalid field triggers the server's field-suggestion ("Did you mean …") response. */
    static String suggestionQuery() {
        return "{\"query\":\"query { __invalidFieldZxq9 }\"}";
    }

    static boolean hasFieldSuggestions(String body) {
        if (body == null) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        return lower.contains("did you mean");
    }

    /** A single request aliasing one cheap field {@code count} times — tests alias amplification. */
    static String aliasQuery(int count) {
        StringBuilder query = new StringBuilder("query {");
        for (int i = 0; i < count; i++) query.append(" a").append(i).append(": __typename");
        query.append(" }");
        return "{\"query\":\"" + LlmProvider.jsonEscape(query.toString()) + "\"}";
    }

    /** True if the response echoes the last alias, i.e. all {@code count} aliases were processed. */
    static boolean aliasingProcessed(String body, int count) {
        return body != null && count > 0 && body.contains("\"a" + (count - 1) + "\"");
    }

    /** A JSON array of two operations — tests whether query batching is enabled. */
    static String batchQuery() {
        return "[{\"query\":\"{__typename}\"},{\"query\":\"{__typename}\"}]";
    }

    static boolean batchingProcessed(String body) {
        if (body == null) return false;
        String trimmed = body.trim();
        return trimmed.startsWith("[") && countOccurrences(trimmed, "\"data\"") >= 2;
    }

    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int at = haystack.indexOf(needle);
        while (at >= 0) {
            count++;
            at = haystack.indexOf(needle, at + needle.length());
        }
        return count;
    }
}
