package com.victor.reconloop;

import java.net.ProxySelector;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Read-only ProjectDiscovery Cloud (PDCP) API client: inspect existing scan status and results.
 * Creating remote target scans is disabled until their egress can be governed. Raw HTTPS with an {@code X-Api-Key} header (and optional {@code X-Team-Id}), mirroring
 * {@link LlmClient} — no SDK is bundled, calls go direct (respecting any system proxy), and the key is
 * never persisted. Responses are parsed with the in-tree {@link Json} parser.
 *
 * <p>Endpoints (base {@code https://api.projectdiscovery.io}):
 * {@code GET /v1/scans/{id}}, {@code GET /v1/scans/results}.
 */
final class PdcpClient {
    private static final String BASE = "https://api.projectdiscovery.io";

    private final HttpClient http;

    PdcpClient() {
        this(HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20))
                .proxy(ProxySelector.getDefault()).followRedirects(HttpClient.Redirect.NEVER).build());
    }

    PdcpClient(HttpClient http) {
        if (http.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("PDCP result reads must not follow redirects");
        }
        this.http = http;
    }

    record ScanCreated(String scanId, String error) {}
    record ScanStatus(String status, int totalResult, double progress, String error) {}
    record Result(String target, String severity, String name, String templateId, String scanId,
                  boolean matched, String request, String response, String vulnId, String vulnStatus) {}

    /** Remote target scans cannot be metered or cancelled per request by this process. */
    ScanCreated createScan(String apiKey, String teamId, String name, List<String> targets,
                           List<String> templates, boolean recommended) {
        return new ScanCreated(null, ExternalTargetEgress.blocked("PDCP scan creation"));
    }

    ScanStatus getScan(String apiKey, String teamId, String scanId) {
        try {
            HttpResponse<String> resp = read("/v1/scans/" + enc(scanId), apiKey, teamId);
            if (resp.statusCode() / 100 != 2) return new ScanStatus(null, 0, 0, "[HTTP " + resp.statusCode() + "]");
            Map<String, Object> o = Json.asObject(unwrap(Json.parse(resp.body())));
            if (o == null) return new ScanStatus(null, 0, 0, "[warning] unexpected status body");
            return new ScanStatus(Json.str(o, "status"), (int) toDouble(o.get("total_result")),
                    toDouble(o.get("progress")), null);
        } catch (Exception e) {
            return new ScanStatus(null, 0, 0, "[error] " + e.getMessage());
        }
    }

    /** Fetches up to {@code limit} results, optionally scoped to the scanned hosts and one scan id. */
    List<Result> getResults(String apiKey, String teamId, List<String> hosts, String scanId, int limit) {
        List<Result> out = new ArrayList<>();
        try {
            StringBuilder path = new StringBuilder("/v1/scans/results?limit=" + Math.max(1, limit) + "&offset=0");
            if (hosts != null && !hosts.isEmpty()) path.append("&host=").append(enc(String.join(",", hosts)));
            HttpResponse<String> resp = read(path.toString(), apiKey, teamId);
            if (resp.statusCode() / 100 != 2) return out;
            for (Object item : extractArray(Json.parse(resp.body()))) {
                Map<String, Object> m = Json.asObject(item);
                if (m == null) continue;
                String rScan = Json.str(m, "scan_id");
                if (scanId != null && rScan != null && !scanId.equals(rScan)) continue;
                Map<String, Object> info = Json.asObject(m.get("info"));
                String name = info != null ? Json.str(info, "name") : Json.str(m, "name");
                String sev = info != null ? Json.str(info, "severity") : Json.str(m, "severity");
                out.add(new Result(
                        nz(Json.str(m, "target")), nz(sev), nz(name), nz(Json.str(m, "template_id")),
                        nz(rScan), Boolean.parseBoolean(String.valueOf(m.get("matcher_status"))),
                        nz(Json.str(m, "request")), nz(Json.str(m, "response")),
                        nz(Json.str(m, "vuln_id")), nz(Json.str(m, "vuln_status"))));
            }
        } catch (Exception ignored) {
            // network/parse failure -> empty result set; caller reports the count
        }
        return out;
    }

    private HttpResponse<String> read(String path, String apiKey, String teamId)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(BASE + path))
                .timeout(Duration.ofSeconds(60))
                .header("X-Api-Key", apiKey == null ? "" : apiKey)
                .header("Content-Type", "application/json");
        if (teamId != null && !teamId.isBlank()) b.header("X-Team-Id", teamId.trim());
        b.GET();
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    /** Unwraps a {@code {"data": ...}} envelope if present. */
    private static Object unwrap(Object root) {
        Map<String, Object> o = Json.asObject(root);
        return o != null && o.get("data") != null ? o.get("data") : root;
    }

    /** Pulls the result array out of a bare array or a {@code data}/{@code results} envelope. */
    private static List<Object> extractArray(Object root) {
        List<Object> arr = Json.asArray(root);
        if (arr != null) return arr;
        Map<String, Object> o = Json.asObject(root);
        if (o != null) {
            List<Object> data = Json.asArray(o.get("data"));
            if (data != null) return data;
            List<Object> results = Json.asArray(o.get("results"));
            if (results != null) return results;
        }
        return List.of();
    }

    private static double toDouble(Object o) {
        if (o instanceof Double d) return d;
        if (o == null) return 0;
        try {
            return Double.parseDouble(String.valueOf(o));
        } catch (Exception e) {
            return 0;
        }
    }

    private static String nz(String v) {
        return v == null ? "" : v;
    }

    private static String enc(String v) {
        return URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8);
    }

}
