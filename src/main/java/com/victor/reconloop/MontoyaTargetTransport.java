package com.victor.reconloop;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.RedirectionMode;
import burp.api.montoya.http.RequestOptions;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.Objects;

/**
 * The only native target HTTP binding. Redirects are deliberately returned to the caller so that
 * every next hop must pass scope, permission, cancellation and quota admission again.
 * Accounting is per Montoya dispatch, not per TCP retransmission performed inside Burp.
 */
final class MontoyaTargetTransport implements ActiveRequestGateway.Sender {
    private final MontoyaApi api;

    MontoyaTargetTransport(MontoyaApi api) {
        this.api = Objects.requireNonNull(api, "api");
    }

    @Override
    public HttpRequestResponse send(HttpRequest request) {
        return api.http().sendRequest(request,
                RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER));
    }
}
