package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Arrays;
import java.util.Objects;

/** Numeric-service binding at the Montoya boundary, not an attestation of Burp's physical socket peer. */
final class MontoyaTargetTransport implements ActiveRequestGateway.PreparedSender {
    private final MontoyaApi api;
    private final DestinationGuard destinations;

    MontoyaTargetTransport(MontoyaApi api) { this(api, DestinationGuard.system()); }

    MontoyaTargetTransport(MontoyaApi api, DestinationGuard destinations) {
        this.api = Objects.requireNonNull(api, "api");
        this.destinations = Objects.requireNonNull(destinations, "destinations");
    }

    @Override public ActiveRequestGateway.Dispatch prepare(HttpRequest request) throws Exception {
        HttpService logical = request.httpService();
        int port = logical.port();
        boolean secure = logical.secure();
        DestinationGuard.Resolved destination = destinations.resolve(logical.host());
        byte[] bytes = request.toByteArray().getBytes().clone();
        HttpRequest pinned = request.withService(HttpService.httpService(destination.address(), port, secure));
        verify(pinned, destination.address(), port, secure, bytes);
        RequestOptions options = RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER);
        if (secure && !destination.serverName().isEmpty()) options = options.withServerNameIndicator(destination.serverName());
        RequestOptions boundOptions = Objects.requireNonNull(options);
        return () -> {
            verify(pinned, destination.address(), port, secure, bytes);
            HttpRequestResponse wire = api.http().sendRequest(pinned, boundOptions);
            // Keep the logical authority in findings/caches while preserving Burp's returned message
            // bytes, annotations, timing and markers. The numeric service is an internal routing choice.
            return wire == null ? null : new LogicalRequestResponse(wire, logical);
        };
    }

    private static void verify(HttpRequest request, String address, int port, boolean secure, byte[] bytes)
            throws DestinationGuard.Rejected {
        HttpService service = request.httpService();
        DestinationAddress.Host actual = DestinationAddress.inspect(service.host());
        if (actual.kind() != DestinationAddress.Kind.PUBLIC || !actual.canonical().equals(address)
                || service.port() != port || service.secure() != secure
                || !Arrays.equals(bytes, request.toByteArray().getBytes())) {
            throw new DestinationGuard.Rejected(RequestPolicy.DecisionCode.DESTINATION_BINDING_FAILED,
                    "numeric service binding changed request bytes or destination");
        }
    }
}
