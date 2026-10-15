package com.victor.reconloop;

import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Passive host and address inventory from public scan and DNS datasets.
 *
 * <p>Each lookup is an explicit call to the provider's API (Shodan, Censys, VirusTotal, FOFA).
 * No request is sent to the target. API keys are read by the caller from the environment and are
 * sent on a direct connection so they never enter Burp's proxy history. Observations are limited
 * to in-zone hostnames and the IP addresses those records name — banners, page bodies, and file
 * samples are ignored.
 */
final class PassiveOsintClient {

    enum Provider {
        SHODAN("Shodan", "SHODAN_API_KEY"),
        CENSYS("Censys", "CENSYS_API_TOKEN"),
        VIRUSTOTAL("VirusTotal", "VIRUSTOTAL_API_KEY"),
        FOFA("FOFA", "FOFA_API_KEY");

        final String display;
        final String envVar;

        Provider(String display, String envVar) {
            this.display = display;
            this.envVar = envVar;
        }
    }

    /** {@code kind} is {@code host}, {@code ipv4}, or {@code ipv6}. */
    record Observation(String kind, String value, String source) {}

    record LookupResult(List<Observation> observations, List<String> notes) {}

    private static final int MAX_BODY_CHARS = 1_500_000;
    private static final int MAX_OBSERVATIONS = 400;
    private static final Duration TIMEOUT = Duration.ofSeconds(25);

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(TIMEOUT)
            .proxy(directOnly())
            .build();

    LookupResult lookup(Provider provider, String domain, String apiKey) {
        String root = CertificateTransparencyClient.normalizeDomain(domain);
        if (root == null) return new LookupResult(List.of(), List.of("Invalid domain."));
        if (apiKey == null || apiKey.isBlank()) {
            return new LookupResult(List.of(), List.of(provider.display + " skipped: set $" + provider.envVar + "."));
        }
        String key = apiKey.trim();
        try {
            HttpRequest request = buildRequest(provider, root, key);
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                return new LookupResult(List.of(), List.of(provider.display + " HTTP " + status + "."));
            }
            String body = response.body() == null ? "" : response.body();
            if (body.length() > MAX_BODY_CHARS) {
                return new LookupResult(List.of(), List.of(provider.display + " response exceeded the size cap."));
            }
            return parse(provider, body, root);
        } catch (Exception e) {
            return new LookupResult(List.of(), List.of(provider.display + " request failed."));
        }
    }

    /** Package-visible so tests can confirm keys stay on the provider host and off the target. */
    static HttpRequest buildRequest(Provider provider, String rootDomain, String apiKey) {
        String root = CertificateTransparencyClient.normalizeDomain(rootDomain);
        if (root == null) throw new IllegalArgumentException("invalid domain");
        return switch (provider) {
            case SHODAN -> HttpRequest.newBuilder()
                    .uri(URI.create("https://api.shodan.io/dns/domain/" + root + "?key=" + urlEncode(apiKey)))
                    .timeout(TIMEOUT)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            case CENSYS -> HttpRequest.newBuilder()
                    .uri(URI.create("https://api.platform.censys.io/v3/global/search/query"))
                    .timeout(TIMEOUT)
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "{\"query\":\"host.dns.names: \\\"" + root + "\\\"\",\"page_size\":50}"))
                    .build();
            case VIRUSTOTAL -> HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/domains/" + root
                            + "/subdomains?limit=40"))
                    .timeout(TIMEOUT)
                    .header("x-apikey", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            case FOFA -> {
                String query = "domain=\"" + root + "\"";
                String qbase64 = Base64.getEncoder().encodeToString(query.getBytes(StandardCharsets.UTF_8));
                yield HttpRequest.newBuilder()
                        .uri(URI.create("https://fofa.info/api/v1/search/all?fields=host,ip,port&size=100&key="
                                + urlEncode(apiKey) + "&qbase64=" + urlEncode(qbase64)))
                        .timeout(TIMEOUT)
                        .header("Accept", "application/json")
                        .GET()
                        .build();
            }
        };
    }

    /**
     * VirusTotal subdomain and resolution documents are separate responses. The controller calls
     * this for each body. {@code resolutions} selects the resolution document shape.
     */
    static LookupResult parse(Provider provider, String json, String rootDomain) {
        return parse(provider, json, rootDomain, false);
    }

    static LookupResult parse(Provider provider, String json, String rootDomain, boolean resolutions) {
        String root = CertificateTransparencyClient.normalizeDomain(rootDomain);
        if (root == null) return new LookupResult(List.of(), List.of("Invalid domain."));
        if (json == null || json.isBlank()) {
            return new LookupResult(List.of(), List.of(provider.display + " returned an empty body."));
        }
        Object parsed;
        try {
            parsed = Json.parse(json);
        } catch (RuntimeException e) {
            return new LookupResult(List.of(), List.of(provider.display + " returned data that was not JSON."));
        }
        Map<String, Object> rootObj = Json.asObject(parsed);
        if (rootObj != null && Boolean.TRUE.equals(rootObj.get("error"))) {
            return new LookupResult(List.of(), List.of(provider.display + " reported an error."));
        }
        LinkedHashSet<String> hosts = new LinkedHashSet<>();
        LinkedHashSet<String> ips = new LinkedHashSet<>();
        List<String> notes = new ArrayList<>();
        switch (provider) {
            case SHODAN -> parseShodan(rootObj, root, hosts, ips, notes);
            case CENSYS -> parseCensys(parsed, root, hosts, ips);
            case VIRUSTOTAL -> {
                if (resolutions) parseVirusTotalResolutions(rootObj, root, hosts, ips);
                else parseVirusTotalSubdomains(rootObj, root, hosts);
            }
            case FOFA -> parseFofa(rootObj, root, hosts, ips);
        }
        return new LookupResult(toObservations(provider, hosts, ips), List.copyOf(notes));
    }

    /** Second VirusTotal call: historical addresses for the domain itself. */
    LookupResult lookupVirusTotalResolutions(String domain, String apiKey) {
        String root = CertificateTransparencyClient.normalizeDomain(domain);
        if (root == null) return new LookupResult(List.of(), List.of("Invalid domain."));
        if (apiKey == null || apiKey.isBlank()) return new LookupResult(List.of(), List.of());
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("https://www.virustotal.com/api/v3/domains/" + root + "/resolutions?limit=40"))
                    .timeout(TIMEOUT)
                    .header("x-apikey", apiKey.trim())
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                return new LookupResult(List.of(), List.of("VirusTotal resolutions HTTP " + response.statusCode() + "."));
            }
            String body = response.body() == null ? "" : response.body();
            if (body.length() > MAX_BODY_CHARS) {
                return new LookupResult(List.of(), List.of("VirusTotal resolutions response exceeded the size cap."));
            }
            return parse(Provider.VIRUSTOTAL, body, root, true);
        } catch (Exception e) {
            return new LookupResult(List.of(), List.of("VirusTotal resolutions request failed."));
        }
    }

    private static void parseShodan(Map<String, Object> root, String zone,
                                    Set<String> hosts, Set<String> ips, List<String> notes) {
        if (root == null) return;
        List<Object> labels = Json.asArray(root.get("subdomains"));
        if (labels != null) {
            for (Object label : labels) {
                if (label instanceof String s) addHost(joinLabel(s, zone), zone, hosts);
            }
        }
        List<Object> rows = Json.asArray(root.get("data"));
        if (rows != null) {
            for (Object row : rows) {
                Map<String, Object> record = Json.asObject(row);
                if (record == null) continue;
                String host = joinLabel(Json.str(record, "subdomain"), zone);
                String type = Json.str(record, "type");
                String value = Json.str(record, "value");
                addHost(host, zone, hosts);
                if (value == null || type == null) continue;
                String kind = type.toUpperCase(Locale.ROOT);
                if ("A".equals(kind) || "AAAA".equals(kind)) addIp(value, ips);
                else if ("CNAME".equals(kind)) addHost(value, zone, hosts);
            }
        }
        if (Boolean.TRUE.equals(root.get("more"))) {
            notes.add("Shodan has more DNS records than the first page.");
        }
    }

    private static void parseCensys(Object node, String zone, Set<String> hosts, Set<String> ips) {
        if (node instanceof List<?> list) {
            for (Object item : list) parseCensys(item, zone, hosts, ips);
            return;
        }
        Map<String, Object> map = Json.asObject(node);
        if (map == null) return;
        Object hits = firstList(map, "hits", "results", "data");
        if (hits instanceof List<?> list && !list.isEmpty() && Json.asObject(list.get(0)) != null) {
            for (Object hit : list) {
                Set<String> hitHosts = new LinkedHashSet<>();
                Set<String> hitIps = new LinkedHashSet<>();
                harvest(hit, zone, hitHosts, hitIps);
                hosts.addAll(hitHosts);
                if (!hitHosts.isEmpty()) ips.addAll(hitIps);
            }
            return;
        }
        for (Object child : map.values()) parseCensys(child, zone, hosts, ips);
    }

    private static void parseVirusTotalSubdomains(Map<String, Object> root, String zone, Set<String> hosts) {
        if (root == null) return;
        List<Object> data = Json.asArray(root.get("data"));
        if (data == null) return;
        for (Object item : data) {
            Map<String, Object> row = Json.asObject(item);
            if (row == null) continue;
            addHost(Json.str(row, "id"), zone, hosts);
        }
    }

    private static void parseVirusTotalResolutions(Map<String, Object> root, String zone,
                                                   Set<String> hosts, Set<String> ips) {
        if (root == null) return;
        List<Object> data = Json.asArray(root.get("data"));
        if (data == null) return;
        for (Object item : data) {
            Map<String, Object> row = Json.asObject(item);
            if (row == null) continue;
            Map<String, Object> attributes = Json.asObject(row.get("attributes"));
            if (attributes == null) continue;
            String host = Json.str(attributes, "host_name");
            if (host != null) addHost(host, zone, hosts);
            String ip = Json.str(attributes, "ip_address");
            if (ip != null && (host == null || inZone(host, zone))) addIp(ip, ips);
        }
    }

    private static void parseFofa(Map<String, Object> root, String zone, Set<String> hosts, Set<String> ips) {
        if (root == null) return;
        List<Object> results = Json.asArray(root.get("results"));
        if (results == null) return;
        for (Object row : results) {
            List<Object> fields = Json.asArray(row);
            if (fields == null || fields.isEmpty()) continue;
            String host = fields.get(0) instanceof String s ? hostOf(s) : null;
            if (!addHost(host, zone, hosts)) continue;
            if (fields.size() > 1 && fields.get(1) instanceof String ip) addIp(ip, ips);
        }
    }

    private static void harvest(Object node, String zone, Set<String> hosts, Set<String> ips) {
        if (node instanceof String s) {
            addHost(hostOf(s), zone, hosts);
            addIp(s.trim(), ips);
            return;
        }
        if (node instanceof List<?> list) {
            for (Object item : list) harvest(item, zone, hosts, ips);
            return;
        }
        Map<String, Object> map = Json.asObject(node);
        if (map == null) return;
        for (Object child : map.values()) harvest(child, zone, hosts, ips);
    }

    private static Object firstList(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value instanceof List<?>) return value;
        }
        return null;
    }

    private static List<Observation> toObservations(Provider provider, Set<String> hosts, Set<String> ips) {
        List<Observation> out = new ArrayList<>();
        String source = provider.display;
        for (String host : hosts) {
            if (out.size() >= MAX_OBSERVATIONS) break;
            out.add(new Observation("host", host, source));
        }
        for (String ip : ips) {
            if (out.size() >= MAX_OBSERVATIONS) break;
            out.add(new Observation(ip.indexOf(':') >= 0 ? "ipv6" : "ipv4", ip, source));
        }
        return List.copyOf(out);
    }

    private static String joinLabel(String label, String zone) {
        if (label == null) return null;
        String value = label.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty() || "@".equals(value)) return zone;
        if (value.endsWith("." + zone) || value.equals(zone)) return value;
        return value + "." + zone;
    }

    private static boolean addHost(String candidate, String zone, Set<String> hosts) {
        if (candidate == null) return false;
        String host = hostOf(candidate);
        if (host == null || !inZone(host, zone)) return false;
        String normalized = CertificateTransparencyClient.normalizeDomain(host);
        if (normalized == null) return false;
        hosts.add(normalized);
        return true;
    }

    private static void addIp(String candidate, Set<String> ips) {
        if (candidate == null) return;
        String value = candidate.trim().toLowerCase(Locale.ROOT);
        if (value.startsWith("[") && value.endsWith("]")) value = value.substring(1, value.length() - 1);
        if (isIpv4(value) || isIpv6(value)) ips.add(value);
    }

    static boolean inZone(String host, String root) {
        String value = host.toLowerCase(Locale.ROOT);
        if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.startsWith("*.")) value = value.substring(2);
        return value.equals(root) || value.endsWith("." + root);
    }

    /** Host portion of a hostname, URL, or host:port token. IPv6 literals are not treated as hosts. */
    static String hostOf(String raw) {
        if (raw == null) return null;
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty() || value.indexOf(' ') >= 0 || value.indexOf('@') >= 0) return null;
        int scheme = value.indexOf("://");
        if (scheme >= 0) value = value.substring(scheme + 3);
        int slash = value.indexOf('/');
        if (slash >= 0) value = value.substring(0, slash);
        if (value.startsWith("*.")) value = value.substring(2);
        if (value.endsWith(".")) value = value.substring(0, value.length() - 1);
        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            return end > 1 ? null : value;
        }
        int colon = value.lastIndexOf(':');
        if (colon > 0 && value.indexOf(':') == colon) value = value.substring(0, colon);
        return value.isEmpty() ? null : value;
    }

    private static boolean isIpv4(String value) {
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return false;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) return false;
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException e) {
                return false;
            }
            if (octet < 0 || octet > 255) return false;
        }
        return true;
    }

    private static boolean isIpv6(String value) {
        int colons = 0;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == ':') colons++;
            else if (Character.digit(c, 16) < 0) return false;
        }
        return colons >= 2 && colons <= 7;
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Never use the JVM proxy. Burp is often that proxy, and Shodan/FOFA put the key in the URL. */
    private static ProxySelector directOnly() {
        return new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
                return List.of(Proxy.NO_PROXY);
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, java.io.IOException ioe) {
                // Direct connection only; the caller records a generic failure.
            }
        };
    }
}
