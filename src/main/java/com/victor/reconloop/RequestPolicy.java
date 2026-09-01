package com.victor.reconloop;

import java.net.URI;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Fail-closed policy for target-directed HTTP requests.
 *
 * <p>This class never resolves host names.  Scope is delegated to the supplied Burp-scope predicate,
 * while literal/private and cloud-metadata destinations are denied before a request can be dispatched.
 */
final class RequestPolicy {
    enum Permission {
        UNSAFE_HTTP_METHOD,
        STATE_CHANGING,
        UPLOAD,
        AUTHENTICATION_OR_LOCKOUT,
        PERSISTENT_PAYLOAD,
        OAST,
        TIME_DELAY
    }

    enum DecisionCode {
        ALLOW,
        RUN_NOT_ACTIVE,
        CANCELLED,
        INVALID_REQUEST,
        OUT_OF_SCOPE,
        PROTECTED_DESTINATION,
        MISSING_PERMISSION,
        BUDGET_EXHAUSTED
    }

    record PlannedRequest(String method, String url, String probeId, Set<Permission> requiredPermissions) {
        PlannedRequest {
            method = method == null ? "" : method.strip().toUpperCase(Locale.ROOT);
            url = url == null ? "" : url.strip();
            probeId = probeId == null || probeId.isBlank() ? "unspecified" : probeId.strip();
            requiredPermissions = requiredPermissions == null || requiredPermissions.isEmpty()
                    ? Set.of() : Set.copyOf(requiredPermissions);
        }

        static PlannedRequest safe(String method, String url, String probeId) {
            return new PlannedRequest(method, url, probeId, Set.of());
        }

        boolean matches(String actualMethod, String actualUrl) {
            String normalizedMethod = actualMethod == null ? "" : actualMethod.strip().toUpperCase(Locale.ROOT);
            String normalizedUrl = actualUrl == null ? "" : actualUrl.strip();
            return method.equals(normalizedMethod) && url.equals(normalizedUrl);
        }
    }

    record Decision(boolean allowed, DecisionCode code, String reason, Set<Permission> missingPermissions) {
        Decision {
            code = Objects.requireNonNull(code, "code");
            reason = reason == null ? "" : reason;
            missingPermissions = missingPermissions == null || missingPermissions.isEmpty()
                    ? Set.of() : Set.copyOf(missingPermissions);
        }

        static Decision allow() {
            return new Decision(true, DecisionCode.ALLOW, "allowed", Set.of());
        }

        static Decision deny(DecisionCode code, String reason) {
            return new Decision(false, code, reason, Set.of());
        }

        static Decision denyMissing(Set<Permission> missing) {
            return new Decision(false, DecisionCode.MISSING_PERMISSION,
                    "missing explicit permission: " + missing, missing);
        }
    }

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");
    private static final Set<String> METADATA_HOSTS = Set.of(
            "metadata.google.internal", "metadata.google", "metadata.aws.internal", "instance-data");

    private final Predicate<String> inScope;
    private final Set<Permission> grantedPermissions;

    RequestPolicy(Predicate<String> inScope, Set<Permission> grantedPermissions) {
        this.inScope = Objects.requireNonNull(inScope, "inScope");
        this.grantedPermissions = grantedPermissions == null || grantedPermissions.isEmpty()
                ? Set.of() : Set.copyOf(grantedPermissions);
    }

    static RequestPolicy safeDefault(Predicate<String> inScope) {
        return new RequestPolicy(inScope, Set.of());
    }

    Decision evaluate(ScanRun run, PlannedRequest request) {
        if (run == null || request == null) return Decision.deny(DecisionCode.INVALID_REQUEST, "run and request are required");
        if (run.isCancelled()) return Decision.deny(DecisionCode.CANCELLED, "run was cancelled");
        if (!run.isRunning()) return Decision.deny(DecisionCode.RUN_NOT_ACTIVE, "run is not running");
        if (request.method().isBlank() || request.url().isBlank()) {
            return Decision.deny(DecisionCode.INVALID_REQUEST, "HTTP method and URL are required");
        }

        URI uri;
        try {
            uri = URI.create(request.url());
        } catch (IllegalArgumentException e) {
            return Decision.deny(DecisionCode.INVALID_REQUEST, "invalid request URL");
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))
                || host == null || host.isBlank()) {
            return Decision.deny(DecisionCode.INVALID_REQUEST, "only absolute HTTP(S) URLs are allowed");
        }
        if (isProtectedDestination(host)) {
            return Decision.deny(DecisionCode.PROTECTED_DESTINATION, "destination is loopback, private, link-local, or metadata");
        }
        try {
            if (!inScope.test(request.url())) return Decision.deny(DecisionCode.OUT_OF_SCOPE, "URL is outside Burp scope");
        } catch (RuntimeException e) {
            return Decision.deny(DecisionCode.OUT_OF_SCOPE, "scope check failed closed");
        }

        EnumSet<Permission> required = request.requiredPermissions().isEmpty()
                ? EnumSet.noneOf(Permission.class) : EnumSet.copyOf(request.requiredPermissions());
        if (!SAFE_METHODS.contains(request.method())) required.add(Permission.UNSAFE_HTTP_METHOD);
        required.removeAll(grantedPermissions);
        if (!required.isEmpty()) return Decision.denyMissing(required);
        return Decision.allow();
    }

    private static boolean isProtectedDestination(String rawHost) {
        String host = rawHost == null ? "" : rawHost.strip().toLowerCase(Locale.ROOT);
        if (host.startsWith("[") && host.endsWith("]") && host.length() > 2) {
            host = host.substring(1, host.length() - 1);
        }
        if (host.isEmpty() || host.equals("localhost") || host.endsWith(".localhost") || METADATA_HOSTS.contains(host)) return true;
        if (host.indexOf(':') >= 0 && (host.equals("::1") || host.equals("::") || host.startsWith("fe8")
                || host.startsWith("fe9") || host.startsWith("fea") || host.startsWith("feb")
                || host.startsWith("fc") || host.startsWith("fd") || host.equals("fd00:ec2::254"))) return true;
        return isProtectedIpv4(host);
    }

    private static boolean isProtectedIpv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) return false;
        int[] octets = new int[4];
        for (int i = 0; i < parts.length; i++) {
            try {
                if (parts[i].isEmpty() || (parts[i].length() > 1 && parts[i].startsWith("+"))) return false;
                octets[i] = Integer.parseInt(parts[i]);
                if (octets[i] < 0 || octets[i] > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        int first = octets[0], second = octets[1];
        return first == 0 || first == 10 || first == 127
                || (first == 172 && second >= 16 && second <= 31)
                || (first == 192 && second == 168)
                || (first == 169 && second == 254);
    }
}
