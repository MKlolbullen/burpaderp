package com.victor.reconloop;

import org.junit.Test;
import java.net.*;
import java.net.http.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import static org.junit.Assert.*;

public class PdcpClientEgressTest {
    @Test public void scanCreationNeverReachesHttpEvenWithCredentialsTargetsAndTemplates() {
        RecordingClient http = new RecordingClient();
        PdcpClient client = new PdcpClient(http);
        var denied = client.createScan("private-key", "team", "scan", List.of("https://example.test"), List.of("all"), true);
        assertNull(denied.scanId());
        assertTrue(denied.error().contains("#44"));
        assertFalse(denied.error().contains("private-key"));
        assertTrue(http.requests.isEmpty());
        assertNull(client.createScan(null, null, null, null, null, false).scanId());
        assertTrue(http.requests.isEmpty());
    }

    @Test public void existingScanReadsRemainGetOnlyAndFixedOriginWithRedirectsDisabled() {
        RecordingClient http = new RecordingClient();
        PdcpClient client = new PdcpClient(http);
        http.body = "{\"status\":\"completed\",\"total_result\":2}";
        assertEquals("completed", client.getScan("key", "team", "../../evil?next=https://evil.test").status());
        http.body = "[{\"scan_id\":\"existing\",\"target\":\"https://example.test\",\"info\":{\"name\":\"test\",\"severity\":\"low\"}}]";
        assertEquals(1, client.getResults("key", "team", List.of("https://evil.test/?x=y"), "existing", 10).size());
        assertEquals(2, http.requests.size());
        for (HttpRequest request : http.requests) {
            assertEquals("GET", request.method());
            assertEquals("https", request.uri().getScheme());
            assertEquals("api.projectdiscovery.io", request.uri().getHost());
            assertTrue(request.bodyPublisher().isEmpty());
        }
        assertEquals(HttpClient.Redirect.NEVER, http.followRedirects());
        http.redirect = HttpClient.Redirect.NORMAL;
        assertThrows(IllegalArgumentException.class, () -> new PdcpClient(http));
    }

    private static final class RecordingClient extends HttpClient {
        final List<HttpRequest> requests = new ArrayList<>();
        String body = "{}";
        Redirect redirect = Redirect.NEVER;
        @Override public Redirect followRedirects() { return redirect; }
        @Override public Optional<CookieHandler> cookieHandler() { return Optional.empty(); }
        @Override public Optional<Duration> connectTimeout() { return Optional.empty(); }
        @Override public Optional<ProxySelector> proxy() { return Optional.empty(); }
        @Override public SSLContext sslContext() { return null; }
        @Override public SSLParameters sslParameters() { return new SSLParameters(); }
        @Override public Optional<Authenticator> authenticator() { return Optional.empty(); }
        @Override public Version version() { return Version.HTTP_1_1; }
        @Override public Optional<Executor> executor() { return Optional.empty(); }
        @SuppressWarnings("unchecked")
        @Override public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
            requests.add(request);
            return (HttpResponse<T>) java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(), new Class<?>[]{HttpResponse.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "statusCode" -> 200;
                        case "body" -> body;
                        case "request" -> request;
                        case "uri" -> request.uri();
                        default -> throw new AssertionError(method.getName());
                    });
        }
        @Override public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler) { throw new AssertionError(); }
        @Override public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> handler, HttpResponse.PushPromiseHandler<T> push) { throw new AssertionError(); }
    }
}
