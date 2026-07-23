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
 * Minimal ProjectDiscovery Cloud (PDCP) API client: create a Nuclei scan, poll its status, and pull
 * results. Raw HTTPS with an {@code X-Api-Key} header (and optional {@code X-Team-Id}), mirroring
 * {@link LlmClient} — no SDK is bundled, calls go direct (respecting any system proxy), and the key is
 * never persisted. Responses are parsed with the in-tree {@link Json} parser.
 *
 * <p>Endpoints (base {@code https://api.projectdiscovery.io}):
 * {@code POST /v1/scans}, {@code GET /v1/scans/{id}}, {@code GET /v1/scans/results}.
 */
final class PdcpClient {
    private static final String BASE = "https://api.projectdiscovery.io";

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .proxy(ProxySelector.getDefault())
            .build();

    record ScanCreated(String scanId, String error) {}
    record ScanStatus(String status, int totalResult, double progress, String error) {}
    record Result(String target, String severity, String name, String templateId, String scanId,
                  boolean matched, String request, String response, String vulnId, String vulnStatus) {}

    /** Creates a scan. When {@code templates} is empty, {@code recommended} should be true. */
    ScanCreated createScan(String apiKey, String teamId, String name, List<String> targets,
                           List<String> templates, boolean recommended) {
        String body = "{"
                + "\"name\":\"" + LlmProvider.jsonEscape(name) + "\","
                + "\"targets\":[" + jsonArray(targets) + "],"
                + "\"templates\":[" + jsonArray(templates) + "],"
                + "\"recommended\":" + recommended
                + "}";
        try {
            HttpResponse<String> resp = send("POST", "/v1/scans", apiKey, teamId, body);
            if (resp.statusCode() / 100 != 2) {
                return new ScanCreated(null, "[HTTP " + resp.statusCode() + "] " + snippet(resp.body()));
            }
            Object root = Json.parse(resp.body());
            String id = findString(root, "scan_id");
            if (id == null) id = findString(root, "id");
            return id != null ? new ScanCreated(id, null)
                    : new ScanCreated(null, "[warning] no scan_id in response: " + snippet(resp.body()));
        } catch (Exception e) {
            return new ScanCreated(null, "[error] " + e.getMessage());
        }
    }

    ScanStatus getScan(String apiKey, String teamId, String scanId) {
        try {
            HttpResponse<String> resp = send("GET", "/v1/scans/" + enc(scanId), apiKey, teamId, null);
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
            HttpResponse<String> resp = send("GET", path.toString(), apiKey, teamId, null);
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

    private HttpResponse<String> send(String method, String path, String apiKey, String teamId, String body)
            throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder()
                .uri(URI.create(BASE + path))
                .timeout(Duration.ofSeconds(60))
                .header("X-Api-Key", apiKey == null ? "" : apiKey)
                .header("Content-Type", "application/json");
        if (teamId != null && !teamId.isBlank()) b.header("X-Team-Id", teamId.trim());
        if ("GET".equals(method)) b.GET();
        else b.method(method, HttpRequest.BodyPublishers.ofString(body == null ? "" : body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static String jsonArray(List<String> items) {
        if (items == null || items.isEmpty()) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) b.append(",");
            b.append("\"").append(LlmProvider.jsonEscape(items.get(i))).append("\"");
        }
        return b.toString();
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

    /** Depth-first search for the first scalar value under {@code key}. */
    private static String findString(Object node, String key) {
        if (node instanceof Map<?, ?> m) {
            Object v = m.get(key);
            if (v != null && !(v instanceof Map) && !(v instanceof List)) return scalar(v);
            for (Object child : m.values()) {
                String r = findString(child, key);
                if (r != null) return r;
            }
        } else if (node instanceof List<?> list) {
            for (Object child : list) {
                String r = findString(child, key);
                if (r != null) return r;
            }
        }
        return null;
    }

    private static String scalar(Object v) {
        if (v instanceof Double d && d == Math.floor(d) && !Double.isInfinite(d)) return String.valueOf((long) (double) d);
        return String.valueOf(v).strip();
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

    private static String snippet(String body) {
        if (body == null) return "(empty)";
        String t = body.strip();
        return t.length() <= 400 ? t : t.substring(0, 397) + "...";
    }
}
