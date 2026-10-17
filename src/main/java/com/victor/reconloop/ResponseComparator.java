package com.victor.reconloop;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Pattern;

/**
 * Deterministic response and timing comparison shared by active verification paths.
 *
 * <p>Volatile values are normalised before page similarity is calculated, so request IDs,
 * timestamps, nonces and CSRF tokens do not create artificial divergence. Timing analysis uses
 * repeated samples, median and median absolute deviation (MAD) rather than a single slow request.
 */
final class ResponseComparator {
    private static final Pattern UUID = Pattern.compile(
            "(?i)\\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\\b");
    private static final Pattern ISO_TIMESTAMP = Pattern.compile(
            "\\b\\d{4}-\\d{2}-\\d{2}[Tt ][0-2]\\d:[0-5]\\d:[0-5]\\d(?:\\.\\d+)?(?:Z|[+-][0-2]\\d:?\\d{2})?\\b");
    private static final Pattern UNIX_TIMESTAMP = Pattern.compile("\\b(?:1[0-9]{9}|1[0-9]{12})\\b");
    private static final Pattern HTML_VOLATILE_VALUE = Pattern.compile(
            "(?i)((?:csrf|xsrf|nonce|request[-_]?id|trace[-_]?id)[^=<>]{0,32}=\\s*[\"']?)[^\"'\\s<>]+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern TOKEN_SPLIT = Pattern.compile("[^a-z0-9_]+");

    private static final Set<String> DEFAULT_VOLATILE_JSON_FIELDS = Set.of(
            "timestamp", "time", "requestid", "request_id", "traceid", "trace_id",
            "correlationid", "correlation_id", "csrf", "csrftoken", "csrf_token",
            "xsrf", "xsrftoken", "xsrf_token", "nonce");

    record TimingAnalysis(boolean delayed,
                          long baselineMedianMillis,
                          long payloadMedianMillis,
                          long baselineMadMillis,
                          long payloadMadMillis,
                          long medianDeltaMillis,
                          int consistentDelayedSamples) {}

    private ResponseComparator() {}

    static boolean samePage(String left, String right) {
        if (left == null || right == null) return false;
        String a = normalizeBody(left);
        String b = normalizeBody(right);
        if (a.equals(b)) return true;

        double tokenSimilarity = similarityNormalized(a, b);
        if (tokenSimilarity >= 0.92) return true;

        int maxLen = Math.max(a.length(), b.length());
        int minLen = Math.min(a.length(), b.length());
        if (maxLen == 0) return true;
        int tolerance = Math.max(5, maxLen / 100);
        if (maxLen - minLen > tolerance) return false;

        // Retain useful behaviour for pages dominated by a single large value while refusing to
        // classify arbitrary same-length pages as equivalent.
        int prefix = commonPrefixLength(a, b);
        return minLen > 0 && (double) prefix / minLen >= 0.90;
    }

    static double similarity(String left, String right) {
        if (left == null || right == null) return 0.0;
        return similarityNormalized(normalizeBody(left), normalizeBody(right));
    }

    static String normalizeBody(String body) {
        if (body == null) return "";
        String trimmed = body.strip();
        if (trimmed.isEmpty()) return "";

        if ((trimmed.startsWith("{") && trimmed.endsWith("}"))
                || (trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                Object parsed = Json.parseStrict(trimmed);
                return Json.write(normalizeJson(parsed, DEFAULT_VOLATILE_JSON_FIELDS));
            } catch (RuntimeException ignored) {
                // Fall through to text normalisation.
            }
        }
        return normalizeText(trimmed);
    }

    static String canonicalizeJson(String json, Set<String> ignoredFields) {
        Object parsed = Json.parseStrict(json == null ? "" : json);
        Set<String> ignored = ignoredFields == null ? Set.of() : ignoredFields;
        return Json.write(normalizeJson(parsed, ignored));
    }

    static TimingAnalysis analyzeTiming(Collection<Long> baselineSamples,
                                        Collection<Long> payloadSamples,
                                        long expectedDelayMillis) {
        List<Long> baseline = sanitizeTimings(baselineSamples);
        List<Long> payload = sanitizeTimings(payloadSamples);
        if (baseline.size() < 3 || payload.size() < 3 || expectedDelayMillis <= 0) {
            return new TimingAnalysis(false, median(baseline), median(payload),
                    mad(baseline), mad(payload), median(payload) - median(baseline), 0);
        }

        long baselineMedian = median(baseline);
        long payloadMedian = median(payload);
        long baselineMad = mad(baseline);
        long payloadMad = mad(payload);
        long delta = payloadMedian - baselineMedian;

        long expectedFloor = Math.max(1_000L, expectedDelayMillis - 1_000L);
        long jitterFloor = Math.max(1_000L, baselineMad * 6L);
        long requiredDelta = Math.max(expectedFloor, jitterFloor);

        int consistent = 0;
        long perSampleFloor = Math.max(1_000L, expectedDelayMillis - 1_500L);
        for (long sample : payload) {
            if (sample - baselineMedian >= perSampleFloor) consistent++;
        }
        int requiredConsistent = (payload.size() * 2 + 2) / 3; // ceil(2n/3)

        boolean delayed = delta >= requiredDelta && consistent >= requiredConsistent;
        return new TimingAnalysis(delayed, baselineMedian, payloadMedian,
                baselineMad, payloadMad, delta, consistent);
    }

    static long median(Collection<Long> values) {
        List<Long> sorted = sanitizeTimings(values);
        if (sorted.isEmpty()) return 0;
        Collections.sort(sorted);
        int middle = sorted.size() / 2;
        if ((sorted.size() & 1) == 1) return sorted.get(middle);
        return Math.round((sorted.get(middle - 1) + sorted.get(middle)) / 2.0);
    }

    static long mad(Collection<Long> values) {
        List<Long> clean = sanitizeTimings(values);
        if (clean.isEmpty()) return 0;
        long med = median(clean);
        List<Long> deviations = new ArrayList<>(clean.size());
        for (long value : clean) deviations.add(Math.abs(value - med));
        return median(deviations);
    }

    private static String normalizeText(String text) {
        String value = UUID.matcher(text).replaceAll("<uuid>");
        value = ISO_TIMESTAMP.matcher(value).replaceAll("<timestamp>");
        value = UNIX_TIMESTAMP.matcher(value).replaceAll("<timestamp>");
        value = HTML_VOLATILE_VALUE.matcher(value).replaceAll("$1<volatile>");
        return WHITESPACE.matcher(value).replaceAll(" ").strip();
    }

    private static Object normalizeJson(Object value, Set<String> ignoredFields) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> sorted = new TreeMap<>();
            for (Map.Entry<?, ?> entry : map.entrySet()) {
                String key = String.valueOf(entry.getKey());
                String normalizedKey = key.toLowerCase(Locale.ROOT);
                if (ignoredFields.stream().map(v -> v.toLowerCase(Locale.ROOT)).anyMatch(normalizedKey::equals)) {
                    continue;
                }
                sorted.put(key, normalizeJson(entry.getValue(), ignoredFields));
            }
            return new LinkedHashMap<>(sorted);
        }
        if (value instanceof List<?> list) {
            List<Object> normalized = new ArrayList<>(list.size());
            for (Object item : list) normalized.add(normalizeJson(item, ignoredFields));
            return normalized;
        }
        if (value instanceof String string) return normalizeText(string);
        return value;
    }

    private static double similarityNormalized(String a, String b) {
        Set<String> left = tokens(a);
        Set<String> right = tokens(b);
        if (left.isEmpty() && right.isEmpty()) return a.equals(b) ? 1.0 : 0.0;
        if (left.isEmpty() || right.isEmpty()) return 0.0;

        Set<String> intersection = new LinkedHashSet<>(left);
        intersection.retainAll(right);
        Set<String> union = new LinkedHashSet<>(left);
        union.addAll(right);
        return union.isEmpty() ? 1.0 : (double) intersection.size() / union.size();
    }

    private static Set<String> tokens(String value) {
        Set<String> out = new LinkedHashSet<>();
        for (String token : TOKEN_SPLIT.split(value.toLowerCase(Locale.ROOT))) {
            if (!token.isBlank()) out.add(token);
        }
        return out;
    }

    private static int commonPrefixLength(String a, String b) {
        int limit = Math.min(a.length(), b.length());
        int i = 0;
        while (i < limit && a.charAt(i) == b.charAt(i)) i++;
        return i;
    }

    private static List<Long> sanitizeTimings(Collection<Long> values) {
        List<Long> out = new ArrayList<>();
        if (values == null) return out;
        for (Long value : values) {
            if (value != null && value >= 0) out.add(value);
        }
        return out;
    }
}
