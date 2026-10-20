package com.victor.reconloop;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.handler.TimingData;
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/** Associate the real returned bytes with the logical service without discarding timing/evidence. */
@SuppressWarnings("removal") // Required compatibility methods in the Montoya 2026.7 interface.
final class LogicalRequestResponse implements HttpRequestResponse {
    private final HttpRequestResponse wire;
    private final HttpService logical;
    private final HttpRequest request;

    LogicalRequestResponse(HttpRequestResponse wire, HttpService logical) {
        this.wire = wire;
        this.logical = logical;
        this.request = wire.request().withService(logical);
        if (!java.util.Arrays.equals(wire.request().toByteArray().getBytes(), request.toByteArray().getBytes()))
            throw new IllegalStateException("logical evidence association changed returned request bytes");
    }

    @Override public HttpRequest request() { return request; }
    @Override public HttpResponse response() { return wire.response(); }
    @Override public HttpService httpService() { return logical; }
    @Override public String url() { return request.url(); }
    @Override public Annotations annotations() { return wire.annotations(); }
    @Override public Optional<TimingData> timingData() { return wire.timingData(); }
    @Override public boolean hasResponse() { return wire.hasResponse(); }
    @Override public ContentType contentType() { return wire.contentType(); }
    @Override public short statusCode() { return wire.statusCode(); }
    @Override public List<Marker> requestMarkers() { return wire.requestMarkers(); }
    @Override public List<Marker> responseMarkers() { return wire.responseMarkers(); }
    @Override public boolean contains(String term, boolean sensitive) { return wire.contains(term, sensitive); }
    @Override public boolean contains(Pattern pattern) { return wire.contains(pattern); }
    @Override public HttpRequestResponse copyToTempFile() { return new LogicalRequestResponse(wire.copyToTempFile(), logical); }
    @Override public HttpRequestResponse withAnnotations(Annotations annotations) { return new LogicalRequestResponse(wire.withAnnotations(annotations), logical); }
    @Override public HttpRequestResponse withRequestMarkers(List<Marker> markers) { return new LogicalRequestResponse(wire.withRequestMarkers(markers), logical); }
    @Override public HttpRequestResponse withRequestMarkers(Marker... markers) { return new LogicalRequestResponse(wire.withRequestMarkers(markers), logical); }
    @Override public HttpRequestResponse withResponseMarkers(List<Marker> markers) { return new LogicalRequestResponse(wire.withResponseMarkers(markers), logical); }
    @Override public HttpRequestResponse withResponseMarkers(Marker... markers) { return new LogicalRequestResponse(wire.withResponseMarkers(markers), logical); }
}
