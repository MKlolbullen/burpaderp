package com.victor.reconloop;

import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Immutable, audit-friendly scope snapshot attached to a {@link ScanRun}.
 *
 * <p>Burp remains the authority for scope enforcement.  This snapshot is deliberately descriptive:
 * it records the target or operator-declared domains/CIDRs that a run was created for without trying
 * to reconstruct Burp's complete project scope.
 */
record ScopeSnapshot(Set<String> domains, Set<String> cidrs) {
    ScopeSnapshot {
        domains = normalize(domains, true);
        cidrs = normalize(cidrs, false);
    }

    static ScopeSnapshot empty() {
        return new ScopeSnapshot(Set.of(), Set.of());
    }

    static ScopeSnapshot forTargetUrl(String targetUrl) {
        try {
            URI uri = URI.create(targetUrl == null ? "" : targetUrl.strip());
            String host = uri.getHost();
            if (host != null && !host.isBlank()) return new ScopeSnapshot(Set.of(host), Set.of());
        } catch (IllegalArgumentException ignored) {
            // The request policy will reject an invalid target; retain an empty audit snapshot here.
        }
        return empty();
    }

    private static Set<String> normalize(Set<String> values, boolean lowerCase) {
        if (values == null || values.isEmpty()) return Set.of();
        Set<String> normalized = new LinkedHashSet<>();
        for (String value : values) {
            if (value == null) continue;
            String trimmed = value.strip();
            if (trimmed.isEmpty()) continue;
            normalized.add(lowerCase ? trimmed.toLowerCase(Locale.ROOT) : trimmed);
        }
        return Set.copyOf(normalized);
    }
}
