package com.victor.reconloop;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;

/** Binds policy metadata to exact Montoya message bytes and the transport destination. No I/O. */
final class RequestPlan {
    private final RequestPolicy.PlannedRequest policyRequest;
    private final Binding binding;

    private RequestPlan(RequestPolicy.PlannedRequest policyRequest, Binding binding) {
        this.policyRequest = policyRequest;
        this.binding = binding;
    }

    static RequestPlan create(HttpRequest request, String probeId, Set<RequestPolicy.Permission> permissions) {
        try {
            return bind(request, new RequestPolicy.PlannedRequest(request.method(), request.url(), probeId, permissions));
        } catch (RuntimeException e) {
            return new RequestPlan(null, null);
        }
    }

    static RequestPlan safe(HttpRequest request, String probeId) {
        return create(request, probeId, Set.of());
    }

    static RequestPlan bind(HttpRequest request, RequestPolicy.PlannedRequest metadata) {
        try {
            Binding binding = Binding.capture(request);
            if (metadata == null || !metadata.matches(request.method(), request.url())) return new RequestPlan(metadata, null);
            // A caller cannot waive upload permission by labeling a multipart replay as another probe.
            var required = withUploadPermission(request, metadata.requiredPermissions());
            return new RequestPlan(new RequestPolicy.PlannedRequest(metadata.method(), metadata.url(),
                    metadata.probeId(), required), binding);
        } catch (RuntimeException e) {
            return new RequestPlan(metadata, null);
        }
    }

    /** All multipart replays need an upload grant, including preserved bodies and safe HTTP methods. */
    static Set<RequestPolicy.Permission> withUploadPermission(HttpRequest request, Set<RequestPolicy.Permission> declared) {
        EnumSet<RequestPolicy.Permission> required = EnumSet.noneOf(RequestPolicy.Permission.class);
        if (declared != null) required.addAll(declared);
        for (var header : request.headers()) {
            if (header.name().equalsIgnoreCase("Content-Type")
                    && header.value().stripLeading().toLowerCase(Locale.ROOT).startsWith("multipart/")) {
                required.add(RequestPolicy.Permission.UPLOAD);
            }
        }
        return Set.copyOf(required);
    }

    RequestPolicy.PlannedRequest policyRequest() { return policyRequest; }

    boolean matches(HttpRequest request) {
        if (binding == null || policyRequest == null || request == null) return false;
        try {
            Binding actual = Binding.capture(request);
            return policyRequest.matches(request.method(), request.url())
                    && binding.host.equals(actual.host) && binding.port == actual.port
                    && binding.secure == actual.secure && Arrays.equals(binding.digest, actual.digest);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private record Binding(String host, int port, boolean secure, byte[] digest) {
        static Binding capture(HttpRequest request) {
            HttpService service = request.httpService();
            URI uri = URI.create(request.url());
            String scheme = uri.getScheme();
            if (service == null || uri.getHost() == null || uri.getRawUserInfo() != null
                    || uri.getRawFragment() != null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
                throw new IllegalArgumentException("invalid transport destination");
            }
            boolean secure = "https".equalsIgnoreCase(scheme);
            int port = uri.getPort() == -1 ? (secure ? 443 : 80) : uri.getPort();
            String host = normalizeHost(service.host());
            if (!host.equals(normalizeHost(uri.getHost())) || service.port() != port
                    || service.secure() != secure || port < 1 || port > 65535) {
                throw new IllegalArgumentException("URL and transport destination disagree");
            }
            byte[] bytes = request.toByteArray().getBytes();
            if (bytes == null || bytes.length == 0) throw new IllegalArgumentException("missing request bytes");
            try {
                return new Binding(host, port, secure, MessageDigest.getInstance("SHA-256").digest(bytes));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("SHA-256 unavailable", e);
            }
        }
        private static String normalizeHost(String host) {
            if (host == null) return "";
            return host.toLowerCase(Locale.ROOT).replaceFirst("^\\[", "").replaceFirst("\\]$", "");
        }
    }
}
