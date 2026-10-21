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
        PREREQUISITE_DENIED,
        PENDING_BINDING,
        PENDING_DESTINATION,
        LOCAL_BUDGET_EXHAUSTED,
        OUT_OF_SCOPE,
        PROTECTED_DESTINATION,
        DESTINATION_UNAVAILABLE,
        DESTINATION_BINDING_FAILED,
        MISSING_PERMISSION,
        BUDGET_EXHAUSTED,
        HOST_BUDGET_EXHAUSTED,
        ENDPOINT_BUDGET_EXHAUSTED,
        PROBE_BUDGET_EXHAUSTED
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
        return evaluate(run, request, true);
    }

    /** Partial preview assessment only; a runtime template has no final URL and cannot authorize dispatch. */
    Decision assessTemplate(ScanRun run, PlannedRequest request) {
        return evaluate(run, request, false);
    }

    private Decision evaluate(ScanRun run, PlannedRequest request, boolean checkScope) {
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
        DestinationAddress.Host destination = DestinationAddress.inspect(host);
        if (destination.kind() == DestinationAddress.Kind.INVALID)
            return Decision.deny(DecisionCode.INVALID_REQUEST, "invalid or ambiguous destination");
        if (destination.kind() == DestinationAddress.Kind.PROTECTED) {
            return Decision.deny(DecisionCode.PROTECTED_DESTINATION, "destination is loopback, private, link-local, or metadata");
        }
        try {
            if (checkScope && !inScope.test(request.url())) return Decision.deny(DecisionCode.OUT_OF_SCOPE, "URL is outside Burp scope");
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

}
